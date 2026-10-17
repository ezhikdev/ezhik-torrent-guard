"""DNS-01 record management.

* cloudflare - API token with Zone.DNS:Edit; fully automatic renewal.
* acmedns    - acme-dns (https://github.com/joohoi/acme-dns); one CNAME per
               _acme-challenge name works with ANY DNS hosting and renews
               automatically. Holds two TXT values per account, which is
               exactly "domain + *.domain"; other names are validated in
               sequence.
* manual     - the panel shows the TXT records; the admin publishes them.
"""

import logging
import os
import time

import dns.exception
import dns.name
import dns.resolver
import httpx

log = logging.getLogger("ezhik.dns")


class DnsError(RuntimeError):
    pass


class Provider:
    automatic = True
    sequential = False

    def present(self, name, values):
        raise NotImplementedError

    def cleanup(self, name, values):
        pass


class ManualProvider(Provider):
    automatic = False

    def present(self, name, values):  # the admin publishes the record
        pass


class CloudflareProvider(Provider):
    API = os.environ.get("EZHIK_CLOUDFLARE_API", "https://api.cloudflare.com/client/v4")

    def __init__(self, token, api=None):
        self.token = token
        self.api = api or self.API
        self._records = {}

    def _call(self, method, path, **kwargs):
        response = httpx.request(method, self.api + path, headers={"Authorization": f"Bearer {self.token}"},
                                 timeout=30, **kwargs)
        try:
            data = response.json()
        except ValueError:
            raise DnsError(f"Cloudflare HTTP {response.status_code}")
        if not data.get("success"):
            errors = "; ".join(e.get("message", "") for e in data.get("errors", []))
            raise DnsError(f"Cloudflare: {errors or response.status_code}")
        return data

    def zone_for(self, name):
        labels = name.rstrip(".").split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            data = self._call("GET", "/zones", params={"name": candidate, "status": "active"})
            if data.get("result"):
                return data["result"][0]["id"]
        raise DnsError(f"Cloudflare: no zone found for {name}")

    def verify(self):
        data = self._call("GET", "/user/tokens/verify")
        return data.get("result", {}).get("status") == "active"

    def present(self, name, values):
        zone = self.zone_for(name)
        for value in values:
            data = self._call("POST", f"/zones/{zone}/dns_records",
                              json={"type": "TXT", "name": name, "content": value, "ttl": 60})
            self._records.setdefault(name, []).append((zone, data["result"]["id"]))

    def cleanup(self, name, values):
        for zone, record_id in self._records.pop(name, []):
            try:
                self._call("DELETE", f"/zones/{zone}/dns_records/{record_id}")
            except Exception as exc:
                log.warning("Cloudflare cleanup of %s failed: %s", name, exc)


class AcmeDnsProvider(Provider):
    sequential = True

    def __init__(self, server, username, password, subdomain):
        self.server = server.rstrip("/")
        self.username, self.password, self.subdomain = username, password, subdomain

    @staticmethod
    def register(server):
        response = httpx.post(server.rstrip("/") + "/register", timeout=30)
        if response.status_code not in (200, 201):
            raise DnsError(f"acme-dns register: HTTP {response.status_code}")
        return response.json()

    def present(self, name, values):
        if len(values) > 2:
            raise DnsError("acme-dns stores at most two TXT values at a time")
        for value in values:
            response = httpx.post(
                self.server + "/update",
                headers={"X-Api-User": self.username, "X-Api-Key": self.password},
                json={"subdomain": self.subdomain, "txt": value}, timeout=30,
            )
            if response.status_code != 200:
                raise DnsError(f"acme-dns update: HTTP {response.status_code} {response.text[:120]}")


def build(provider_row, secrets_box, resolvers=None):
    if provider_row is None:
        return ManualProvider()
    import json

    creds = json.loads(secrets_box.decrypt(provider_row["credentials"]) or "{}") if provider_row.get("credentials") else {}
    kind = provider_row["type"]
    if kind == "cloudflare":
        return CloudflareProvider(creds.get("token"), creds.get("api"))
    if kind == "acmedns":
        return AcmeDnsProvider(creds["server"], creds["username"], creds["password"], creds["subdomain"])
    return ManualProvider()


# ------------------------------------------------------------- propagation


class Propagation:
    def __init__(self, resolvers, port=53):
        self.resolvers = resolvers or ["1.1.1.1", "8.8.8.8"]
        self.port = int(port)

    def _authoritative_ips(self, name):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self.resolvers
        resolver.port = self.port
        resolver.lifetime = 8
        labels = dns.name.from_text(name)
        while len(labels.labels) > 2:
            try:
                answer = resolver.resolve(labels, "NS")
                ips = []
                for record in answer:
                    try:
                        ips += [a.address for a in resolver.resolve(record.target, "A")]
                    except dns.exception.DNSException:
                        pass
                if ips:
                    return ips
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.exception.DNSException:
                break
            labels = labels.parent()
        return []

    def lookup(self, name, nameservers=None):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = nameservers or self.resolvers
        resolver.port = 53 if nameservers else self.port
        resolver.lifetime = 8
        resolver.cache = None
        try:
            answer = resolver.resolve(name, "TXT")
            return {b"".join(r.strings).decode("utf-8", "replace") for r in answer}
        except dns.exception.DNSException:
            return set()

    def visible(self, name, values):
        """True when every value is served by the authoritative and public resolvers."""
        values = set(values)
        if not values <= self.lookup(name):
            return False
        authoritative = self._authoritative_ips(name)
        if authoritative and not values <= self.lookup(name, authoritative):
            # A CNAME (acme-dns) target is answered by public resolvers.
            return values <= self.lookup(name)
        return True

    def wait(self, records, timeout=600, interval=10, on_progress=None):
        """records: {name: [values]}. Raises DnsError on timeout."""
        deadline = time.monotonic() + timeout
        pending = dict(records)
        while pending:
            for name in list(pending):
                if self.visible(name, pending[name]):
                    pending.pop(name)
            if not pending:
                return
            if on_progress:
                on_progress(sorted(pending))
            if time.monotonic() > deadline:
                raise DnsError("TXT records are not visible yet: " + ", ".join(sorted(pending)))
            time.sleep(interval)

