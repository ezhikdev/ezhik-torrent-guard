"""Certificate lifecycle: issue, renew, import, store, distribute."""

import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import acme as acme_mod
from . import dns_providers
from .db import loads

log = logging.getLogger("ezhik.certs")

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class CertError(ValueError):
    pass


# ---------------------------------------------------------------- domains


def normalize_domain(value):
    value = str(value).strip().lower().rstrip(".")
    wildcard = value.startswith("*.")
    body = value[2:] if wildcard else value
    if "*" in body:
        raise CertError(f"{value}: «*» допускается только как первая метка (*.example.com)")
    try:
        body = body.encode("idna").decode("ascii")
    except UnicodeError:
        raise CertError(f"{value}: недопустимое доменное имя")
    labels = body.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(label) for label in labels) or labels[-1].isdigit():
        raise CertError(f"{value}: недопустимое доменное имя")
    if len(body) > 253:
        raise CertError(f"{value}: имя длиннее 253 символов")
    return ("*." + body) if wildcard else body


def normalize_domains(values):
    out = []
    for raw in values:
        for part in re.split(r"[\s,;]+", str(raw)):
            if part:
                domain = normalize_domain(part)
                if domain not in out:
                    out.append(domain)
    if not out:
        raise CertError("Укажите хотя бы один домен")
    if len(out) > 100:
        raise CertError("Не более 100 имён в одном сертификате")
    return out


def covers(names, host):
    host = host.lower().rstrip(".")
    if host in names:
        return True
    parts = host.split(".", 1)
    return len(parts) == 2 and f"*.{parts[1]}" in names


def analyze(domains):
    """Human hints about what a set of names does and does not cover."""
    hints = []
    names = set(domains)
    for domain in domains:
        if domain.startswith("*."):
            base = domain[2:]
            if base not in names:
                hints.append({
                    "level": "info",
                    "text": f"{domain} не покрывает сам {base}. Добавьте {base}, если он тоже нужен.",
                    "suggest": base,
                })
            hints.append({
                "level": "info",
                "text": f"{domain} покрывает только один уровень: например x.{base}, но не a.b.{base}. "
                        f"Для более глубоких имён добавьте отдельный wildcard (*.sub.{base}).",
            })
    seen = set()
    for domain in domains:
        record = acme_mod.challenge_name(domain)
        if record not in seen:
            seen.add(record)
    hints.append({"level": "info", "text": "TXT-записи для проверки: " + ", ".join(sorted(seen))})
    return hints


def parse_certificate(pem):
    certs = x509.load_pem_x509_certificates(pem.encode("ascii"))
    if not certs:
        raise CertError("PEM не содержит сертификата")
    leaf = certs[0]
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    return {
        "names": list(san),
        "not_before": leaf.not_valid_before_utc.timestamp(),
        "not_after": leaf.not_valid_after_utc.timestamp(),
        "issuer": leaf.issuer.rfc4514_string()[:200],
        "fingerprint": leaf.fingerprint(hashes.SHA256()).hex(),
        "public_key": leaf.public_key().public_bytes(serialization.Encoding.DER,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo),
    }


def key_matches(cert_info, key_pem_text):
    key = serialization.load_pem_private_key(key_pem_text.encode("ascii"), None)
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return public == cert_info["public_key"]


# ---------------------------------------------------------------- service


class CertificateService:
    def __init__(self, db, settings, secrets, events, config, on_change):
        self.db = db
        self.settings = settings
        self.secrets = secrets
        self.events = events
        self.config = config
        self.on_change = on_change  # callable(cert_id): wake affected nodes
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="acme")
        self.running = set()
        self._lock = threading.Lock()
        self.acme_verify = os.environ.get("EZHIK_ACME_CA_BUNDLE") or True
        self.propagation = dns_providers.Propagation(config.dns_resolvers, os.environ.get("EZHIK_DNS_PORT", "53"))
        self.propagation_timeout = int(os.environ.get("EZHIK_DNS_PROPAGATION_TIMEOUT", "600"))

    # ------------------------------------------------------------ queries

    def get(self, cert_id):
        row = self.db.one("SELECT * FROM certificates WHERE id=?", (cert_id,))
        if not row:
            raise LookupError("Сертификат не найден")
        return self._public(row)

    def _public(self, row):
        row = dict(row)
        row["domains"] = loads(row["domains"], [])
        row["challenge"] = loads(row["challenge"], None)
        row["nodes"] = self.db.all("SELECT id, name, domain FROM nodes WHERE cert_id=? ORDER BY name", (row["id"],))
        row["running"] = row["id"] in self.running
        provider = self.db.one("SELECT * FROM dns_providers WHERE id=?", (row["provider_id"],)) if row["provider_id"] else None
        row["provider"] = provider_public(provider, self.secrets) if provider else None
        return row

    def list(self):
        return [self._public(r) for r in self.db.all("SELECT * FROM certificates ORDER BY created_at DESC")]

    def paths(self, cert_id):
        root = self.config.certs_dir / cert_id
        return root / "fullchain.pem", root / "privkey.pem"

    # ------------------------------------------------------------- create

    def create(self, name, domains, provider_id, key_type="ec256", auto_renew=True, actor="admin"):
        domains = normalize_domains(domains)
        if key_type not in ("ec256", "ec384", "rsa2048", "rsa4096"):
            raise CertError("Неизвестный тип ключа")
        provider = None
        if provider_id:
            provider = self.db.one("SELECT * FROM dns_providers WHERE id=?", (provider_id,))
            if not provider:
                raise CertError("DNS-провайдер не найден")
        if not self.settings.acme().get("email"):
            raise CertError("Укажите e-mail ACME в настройках сертификатов")
        cert_id = uuid.uuid4().hex[:12]
        now = time.time()
        self.db.execute(
            "INSERT INTO certificates(id,name,domains,source,provider_id,key_type,status,auto_renew,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (cert_id, (name or domains[0])[:120], json.dumps(domains), "acme", provider_id, key_type, "new",
             1 if auto_renew else 0, now, now),
        )
        self.db.audit(actor, "cert.create", cert_id, {"domains": domains})
        self.start_issue(cert_id)
        return self.get(cert_id)

    def upload(self, name, fullchain, privkey, actor="admin"):
        fullchain, privkey = fullchain.strip() + "\n", privkey.strip() + "\n"
        try:
            info = parse_certificate(fullchain)
            if not key_matches(info, privkey):
                raise CertError("Закрытый ключ не соответствует сертификату")
        except CertError:
            raise
        except Exception as exc:
            raise CertError(f"Не удалось разобрать PEM: {exc}")
        cert_id = uuid.uuid4().hex[:12]
        self._store(cert_id, fullchain, privkey)
        now = time.time()
        self.db.execute(
            "INSERT INTO certificates(id,name,domains,source,key_type,status,auto_renew,version,issued_at,not_before,"
            "not_after,fingerprint,issuer,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cert_id, (name or (info["names"] or ["certificate"])[0])[:120], json.dumps(info["names"]), "upload",
             "imported", "valid" if info["not_after"] > now else "expired", 0, 1, now, info["not_before"],
             info["not_after"], info["fingerprint"], info["issuer"], now, now),
        )
        self.db.audit(actor, "cert.upload", cert_id, {"domains": info["names"]})
        return self.get(cert_id)

    def update(self, cert_id, name=None, auto_renew=None, provider_id=None, domains=None, actor="admin"):
        cert = self.get(cert_id)
        fields = {}
        if name is not None:
            fields["name"] = name[:120]
        if auto_renew is not None:
            fields["auto_renew"] = 1 if auto_renew else 0
        if provider_id is not None and cert["source"] == "acme":
            fields["provider_id"] = provider_id or None
        if domains is not None and cert["source"] == "acme":
            fields["domains"] = json.dumps(normalize_domains(domains))
        if fields:
            fields["updated_at"] = time.time()
            sets = ", ".join(f"{k}=?" for k in fields)
            self.db.execute(f"UPDATE certificates SET {sets} WHERE id=?", (*fields.values(), cert_id))
            self.db.audit(actor, "cert.update", cert_id, {k: v for k, v in fields.items() if k != "updated_at"})
        return self.get(cert_id)

    def delete(self, cert_id, actor="admin"):
        cert = self.get(cert_id)
        if cert["nodes"]:
            raise CertError("Сертификат назначен нодам: " + ", ".join(n["name"] for n in cert["nodes"]))
        if self.settings.panel().get("web_cert_id") == cert_id:
            raise CertError("Сертификат используется веб-интерфейсом панели")
        self.db.execute("DELETE FROM certificates WHERE id=?", (cert_id,))
        shutil.rmtree(self.config.certs_dir / cert_id, ignore_errors=True)
        self.db.audit(actor, "cert.delete", cert_id, {"domains": cert["domains"]})

    # ----------------------------------------------------------- issuance

    def start_issue(self, cert_id):
        with self._lock:
            if cert_id in self.running:
                return False
            self.running.add(cert_id)
        self.pool.submit(self._issue_job, cert_id)
        return True

    def _set(self, cert_id, **fields):
        fields["updated_at"] = time.time()
        sets = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE certificates SET {sets} WHERE id=?", (*fields.values(), cert_id))

    def _progress(self, cert_id, stage, **extra):
        current = loads(self.db.scalar("SELECT challenge FROM certificates WHERE id=?", (cert_id,)), {}) or {}
        current.update({"stage": stage, "at": time.time(), **extra})
        self._set(cert_id, challenge=json.dumps(current, ensure_ascii=False))

    def _account(self, client):
        acme_cfg = self.settings.acme()
        key = f"acme_account:{acme_cfg['directory']}"
        stored = self.db.get_json(key)
        if stored and stored.get("key"):
            client.key = acme_mod.serialization.load_pem_private_key(stored["key"].encode(), None)
            client.kid = stored.get("kid")
            if client.kid:
                return
        client.register(acme_cfg.get("email"))
        self.db.set_json(key, {"key": client.account_key_pem, "kid": client.kid, "email": acme_cfg.get("email")})

    def _client(self):
        return acme_mod.AcmeClient(self.settings.acme()["directory"], verify=self.acme_verify)

    def _issue_job(self, cert_id):
        try:
            self._issue(cert_id)
        except Exception as exc:
            log.exception("Issuance of %s failed", cert_id)
            row = self.db.one("SELECT * FROM certificates WHERE id=?", (cert_id,))
            if row:
                had_valid = row["version"] > 0 and (row["not_after"] or 0) > time.time()
                self._set(cert_id, status="valid" if had_valid else "failed", last_error=str(exc)[:600],
                          next_attempt_at=time.time() + 6 * 3600)
                self._progress(cert_id, "failed", error=str(exc)[:600])
                domains = loads(row["domains"], [])
                self.events.record_system("cert", f"Ошибка выпуска сертификата {row['name']}: {str(exc)[:200]}",
                                          "error", data={"cert_id": cert_id, "domains": domains})
        finally:
            with self._lock:
                self.running.discard(cert_id)

    def _issue(self, cert_id):
        row = self.db.one("SELECT * FROM certificates WHERE id=?", (cert_id,))
        if not row or row["source"] != "acme":
            return
        domains = loads(row["domains"], [])
        provider_row = self.db.one("SELECT * FROM dns_providers WHERE id=?", (row["provider_id"],)) if row["provider_id"] else None
        provider = dns_providers.build(provider_row, self.secrets)
        manual_state = loads(row["challenge"], {}) or {}
        client = self._client()
        try:
            self._set(cert_id, status="issuing", last_attempt_at=time.time(), last_error=None)
            self._progress(cert_id, "account")
            self._account(client)

            # Manual DNS resumes the order prepared earlier.
            order = None
            if not provider.automatic and manual_state.get("order_url") and manual_state.get("confirmed"):
                order = client.get(manual_state["order_url"])
                order["url"] = manual_state["order_url"]
                if order.get("status") not in ("pending", "ready"):
                    order = None
            if order is None:
                self._progress(cert_id, "order")
                order = client.new_order(domains)
            challenges = client.challenges(order)
            records = {}
            for ch in challenges:
                records.setdefault(ch["name"], []).append(ch["value"])

            if not provider.automatic and not manual_state.get("confirmed"):
                self._set(cert_id, status="pending_dns")
                self._progress(cert_id, "pending_dns", order_url=order["url"], confirmed=False,
                               records=[{"name": n, "values": v} for n, v in records.items()])
                self.events.record_system(
                    "cert", f"Сертификат {row['name']}: требуется опубликовать TXT-записи", "warn",
                    data={"cert_id": cert_id, "records": records})
                return

            groups = [list(records.items())] if not provider.sequential else [[item] for item in records.items()]
            for group in groups:
                if provider.automatic:
                    for name, values in group:
                        self._progress(cert_id, "dns_publish", pending=[name])
                        provider.present(name, values)
                try:
                    self._progress(cert_id, "dns_wait", pending=[n for n, _ in group])
                    self.propagation.wait(dict(group), timeout=self.propagation_timeout,
                                          on_progress=lambda pending: self._progress(cert_id, "dns_wait", pending=pending))
                    self._progress(cert_id, "validating")
                    group_names = {n for n, _ in group}
                    for ch in challenges:
                        if ch["name"] in group_names:
                            client.answer(ch["url"])
                    for ch in challenges:
                        if ch["name"] in group_names:
                            client.wait_authz(ch["authz"])
                finally:
                    if provider.automatic:
                        for name, values in group:
                            provider.cleanup(name, values)

            self._progress(cert_id, "finalizing")
            key = acme_mod.generate_key(row["key_type"])
            fullchain = client.finalize(order, acme_mod.make_csr(key, domains))
            privkey = acme_mod.key_pem(key)
            info = parse_certificate(fullchain)
            missing = [d for d in domains if d not in info["names"]]
            if missing or not key_matches(info, privkey):
                raise CertError("Выпущенный сертификат не соответствует запросу: " + ", ".join(missing))
            self._store(cert_id, fullchain, privkey)
            self.db.execute(
                "UPDATE certificates SET status='valid', version=version+1, issued_at=?, not_before=?, not_after=?, "
                "fingerprint=?, issuer=?, last_error=NULL, next_attempt_at=NULL, challenge=NULL, updated_at=? WHERE id=?",
                (time.time(), info["not_before"], info["not_after"], info["fingerprint"], info["issuer"],
                 time.time(), cert_id),
            )
            self.events.record_system("cert", f"Сертификат {row['name']} выпущен до "
                                      + time.strftime("%d.%m.%Y", time.localtime(info["not_after"])),
                                      data={"cert_id": cert_id, "domains": domains})
            log.info("Certificate %s issued for %s", cert_id, ", ".join(domains))
            self.on_change(cert_id)
        finally:
            client.close()

    def confirm_manual(self, cert_id):
        """Admin published the TXT records: check them and continue."""
        row = self.db.one("SELECT * FROM certificates WHERE id=?", (cert_id,))
        state = loads(row["challenge"], {}) if row else {}
        if not row or row["status"] != "pending_dns" or not state.get("records"):
            raise CertError("Сертификат не ожидает публикации DNS-записей")
        missing = []
        for record in state["records"]:
            if not self.propagation.visible(record["name"], record["values"]):
                missing.append(record["name"])
        if missing:
            return {"ok": False, "missing": missing}
        state["confirmed"] = True
        self._set(cert_id, challenge=json.dumps(state))
        self.start_issue(cert_id)
        return {"ok": True}

    def check_records(self, cert_id):
        cert = self.get(cert_id)
        state = cert.get("challenge") or {}
        result = []
        for record in state.get("records") or []:
            found = self.propagation.lookup(record["name"])
            result.append({"name": record["name"], "values": record["values"],
                           "found": sorted(found), "ok": set(record["values"]) <= found})
        return result

    def _store(self, cert_id, fullchain, privkey):
        root = self.config.certs_dir / cert_id
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        for name, content, mode in (("fullchain.pem", fullchain, 0o644), ("privkey.pem", privkey, 0o600)):
            tmp = root / (name + ".tmp")
            tmp.write_text(content, encoding="ascii")
            os.chmod(tmp, mode)
            os.replace(tmp, root / name)

    # ------------------------------------------------------------- renewal

    def renew_due(self):
        acme_cfg = self.settings.acme()
        now = time.time()
        threshold = now + acme_cfg["renew_days"] * 86400
        for row in self.db.all("SELECT * FROM certificates WHERE source='acme' AND auto_renew=1"):
            if row["id"] in self.running:
                continue
            if row["next_attempt_at"] and row["next_attempt_at"] > now:
                continue
            due = row["status"] in ("new", "failed") or bool(row["not_after"] and row["not_after"] < threshold)
            if row["status"] == "pending_dns":
                continue
            if due:
                log.info("Renewing certificate %s", row["id"])
                if row["provider_id"] is None:
                    # Manual DNS: prepare a new order and ask the admin.
                    self._set(row["id"], challenge=None)
                self.start_issue(row["id"])
        for row in self.db.all("SELECT id, name, not_after, status FROM certificates WHERE status='valid'"):
            if row["not_after"] and row["not_after"] < now:
                self._set(row["id"], status="expired")
                self.events.record_system("cert", f"Сертификат {row['name']} истёк", "error", data={"cert_id": row["id"]})

    # --------------------------------------------------------------- nodes

    def bundle(self, cert_id):
        row = self.db.one("SELECT * FROM certificates WHERE id=?", (cert_id,))
        if not row or not row["version"]:
            raise LookupError("certificate not issued")
        cert_path, key_path = self.paths(cert_id)
        return {
            "certificate_id": cert_id,
            "version": row["version"],
            "domains": loads(row["domains"], []),
            "fullchain_pem": cert_path.read_text(encoding="ascii"),
            "privkey_pem": key_path.read_text(encoding="ascii"),
        }


def provider_public(row, secrets):
    creds = {}
    if row.get("credentials"):
        try:
            creds = json.loads(secrets.decrypt(row["credentials"]) or "{}")
        except ValueError:
            creds = {}
    out = {"id": row["id"], "name": row["name"], "type": row["type"], "created_at": row["created_at"]}
    if row["type"] == "acmedns":
        out["fulldomain"] = creds.get("fulldomain")
        out["server"] = creds.get("server")
    if row["type"] == "cloudflare":
        token = creds.get("token") or ""
        out["token_hint"] = ("…" + token[-4:]) if token else ""
    return out


__all__ = ["CertificateService", "CertError", "normalize_domains", "analyze", "covers", "provider_public", "Path"]
