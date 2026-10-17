"""Private CA for the agent channel and a default HTTPS certificate for the UI."""

import base64
import datetime as dt
import hashlib
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _now():
    return dt.datetime.now(dt.timezone.utc)


class PKI:
    def __init__(self, directory):
        self.dir = Path(directory)
        self.ca_key_path = self.dir / "ca.key"
        self.ca_cert_path = self.dir / "ca.pem"
        self.server_key_path = self.dir / "server.key"
        self.server_cert_path = self.dir / "server.pem"

    def ensure(self, names):
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            self._create_ca()
        if not self._server_valid(names):
            self._issue_server(names)

    def _create_ca(self):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ezhik Guard"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Ezhik Guard Panel CA"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(days=1))
            .not_valid_after(_now() + dt.timedelta(days=365 * 25))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        _write(self.ca_key_path, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600)
        _write(self.ca_cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)

    def _server_valid(self, names):
        try:
            cert = x509.load_pem_x509_certificate(self.server_cert_path.read_bytes())
            if cert.not_valid_after_utc - _now() < dt.timedelta(days=30):
                return False
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            present = {str(v) for v in san.get_values_for_type(x509.IPAddress)} | set(san.get_values_for_type(x509.DNSName))
            return set(names) <= present
        except Exception:
            return False

    def _issue_server(self, names):
        ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), None)
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        key = ec.generate_private_key(ec.SECP256R1())
        alt = []
        for name in sorted(set(names) | {"localhost", "127.0.0.1"}):
            try:
                alt.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                alt.append(x509.DNSName(name))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ezhik Guard Panel")]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(days=1))
            .not_valid_after(_now() + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        _write(self.server_key_path, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600)
        chain = cert.public_bytes(serialization.Encoding.PEM) + self.ca_cert_path.read_bytes()
        _write(self.server_cert_path, chain, 0o644)

    @property
    def ca_pem(self):
        return self.ca_cert_path.read_text(encoding="ascii")

    def server_pin(self):
        """curl --pinnedpubkey value for the agent endpoint."""
        cert = x509.load_pem_x509_certificate(self.server_cert_path.read_bytes())
        spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return "sha256//" + base64.b64encode(hashlib.sha256(spki).digest()).decode()

    def ca_fingerprint(self):
        cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        return cert.fingerprint(hashes.SHA256()).hex()
