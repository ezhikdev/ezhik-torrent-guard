"""Minimal, complete RFC 8555 ACME client for DNS-01 (Let's Encrypt et al.).

Wildcards at any depth are plain identifiers: ``*.sub.test.example.com`` is
validated with a TXT record at ``_acme-challenge.sub.test.example.com``.
An apex and its wildcard (``example.com`` + ``*.example.com``) share one
record name with two TXT values; providers receive all values per name.
"""

import base64
import hashlib
import json
import logging
import time

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from . import __version__

log = logging.getLogger("ezhik.acme")


class AcmeError(RuntimeError):
    def __init__(self, message, problem=None):
        self.problem = problem or {}
        super().__init__(message)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def challenge_name(identifier):
    base = identifier[2:] if identifier.startswith("*.") else identifier
    return f"_acme-challenge.{base.rstrip('.').lower()}"


def generate_key(key_type):
    if key_type == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "rsa4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if key_type == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


def make_csr(key, domains):
    common = next((d for d in domains if not d.startswith("*.")), domains[0])
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common[:64])]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


class AcmeClient:
    def __init__(self, directory_url, account_key_pem=None, kid=None, timeout=30, verify=True):
        self.directory_url = directory_url
        self.http = httpx.Client(timeout=timeout, verify=verify,
                                 headers={"User-Agent": f"ezhik-guard-acme/{__version__}"})
        if account_key_pem:
            self.key = serialization.load_pem_private_key(account_key_pem.encode("ascii"), None)
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = kid
        self._directory = None
        self._nonce = None

    def close(self):
        self.http.close()

    @property
    def account_key_pem(self):
        return key_pem(self.key)

    # ------------------------------------------------------------- JWS

    def jwk(self):
        numbers = self.key.public_key().public_numbers()
        return {
            "crv": "P-256", "kty": "EC",
            "x": b64(numbers.x.to_bytes(32, "big")),
            "y": b64(numbers.y.to_bytes(32, "big")),
        }

    def thumbprint(self):
        jwk = json.dumps(self.jwk(), sort_keys=True, separators=(",", ":")).encode()
        return b64(hashlib.sha256(jwk).digest())

    def directory(self):
        if self._directory is None:
            response = self.http.get(self.directory_url)
            response.raise_for_status()
            self._directory = response.json()
        return self._directory

    def _new_nonce(self):
        response = self.http.head(self.directory()["newNonce"])
        nonce = response.headers.get("Replay-Nonce")
        if not nonce:
            raise AcmeError("ACME server did not return a nonce")
        return nonce

    def _sign(self, url, payload, use_jwk=False):
        protected = {"alg": "ES256", "nonce": self._nonce or self._new_nonce(), "url": url}
        self._nonce = None
        if use_jwk or not self.kid:
            protected["jwk"] = self.jwk()
        else:
            protected["kid"] = self.kid
        protected_b64 = b64(json.dumps(protected).encode())
        payload_b64 = "" if payload is None else b64(json.dumps(payload).encode())
        der = self.key.sign(f"{protected_b64}.{payload_b64}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return {"protected": protected_b64, "payload": payload_b64, "signature": signature}

    def post(self, url, payload, use_jwk=False, accept=None, retries=2):
        for attempt in range(retries + 1):
            body = self._sign(url, payload, use_jwk)
            headers = {"Content-Type": "application/jose+json"}
            if accept:
                headers["Accept"] = accept
            response = self.http.post(url, content=json.dumps(body), headers=headers)
            self._nonce = response.headers.get("Replay-Nonce")
            if response.status_code < 400:
                return response
            problem = _problem(response)
            if problem.get("type", "").endswith(":badNonce") and attempt < retries:
                continue
            if response.status_code in (429, 503) and attempt < retries:
                time.sleep(min(30, int(response.headers.get("Retry-After", "5") or 5)))
                continue
            raise AcmeError(f"ACME {problem.get('type', response.status_code)}: {problem.get('detail', response.text[:200])}", problem)
        raise AcmeError("ACME request failed")

    def get(self, url):
        """POST-as-GET."""
        return self.post(url, None).json()

    # --------------------------------------------------------- account

    def register(self, email):
        payload = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = [f"mailto:{email}"]
        response = self.post(self.directory()["newAccount"], payload, use_jwk=True)
        self.kid = response.headers["Location"]
        return self.kid

    # ----------------------------------------------------------- order

    def new_order(self, domains):
        response = self.post(self.directory()["newOrder"],
                             {"identifiers": [{"type": "dns", "value": d} for d in domains]})
        order = response.json()
        order["url"] = response.headers["Location"]
        return order

    def challenges(self, order):
        """Return pending dns-01 challenges: [{identifier, name, value, url, authz}]"""
        out = []
        thumb = self.thumbprint()
        for authz_url in order["authorizations"]:
            authz = self.get(authz_url)
            if authz["status"] == "valid":
                continue
            if authz["status"] != "pending":
                raise AcmeError(f"authorization for {authz['identifier']['value']} is {authz['status']}")
            identifier = authz["identifier"]["value"]
            if authz.get("wildcard"):
                identifier = "*." + identifier
            dns01 = next((c for c in authz["challenges"] if c["type"] == "dns-01"), None)
            if not dns01:
                raise AcmeError(f"no dns-01 challenge offered for {identifier}")
            key_authorization = f"{dns01['token']}.{thumb}"
            out.append({
                "identifier": identifier,
                "name": challenge_name(identifier),
                "value": b64(hashlib.sha256(key_authorization.encode()).digest()),
                "url": dns01["url"],
                "authz": authz_url,
            })
        return out

    def answer(self, challenge_url):
        self.post(challenge_url, {})

    def wait_authz(self, authz_url, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            authz = self.get(authz_url)
            if authz["status"] == "valid":
                return
            if authz["status"] in ("invalid", "deactivated", "expired", "revoked"):
                detail = ""
                for chall in authz.get("challenges", []):
                    if chall.get("error"):
                        detail = chall["error"].get("detail", "")
                raise AcmeError(f"validation of {authz['identifier']['value']} failed: {detail}")
            time.sleep(3)
        raise AcmeError("timed out waiting for the CA to validate the DNS record")

    def finalize(self, order, csr_der, timeout=180):
        self.post(order["finalize"], {"csr": b64(csr_der)})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self.get(order["url"])
            if current["status"] == "valid":
                response = self.post(current["certificate"], None, accept="application/pem-certificate-chain")
                return response.text
            if current["status"] == "invalid":
                raise AcmeError(f"order became invalid: {current.get('error', {}).get('detail', '')}")
            time.sleep(2)
        raise AcmeError("timed out waiting for the certificate")


def _problem(response):
    try:
        data = response.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {"detail": response.text[:200]}
