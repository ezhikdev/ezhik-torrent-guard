"""Passwords, tokens and at-rest encryption of stored secrets."""

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    )


def verify_password(password, stored):
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=base64.b64decode(salt),
            n=int(n), r=int(r), p=int(p), dklen=len(base64.b64decode(digest)),
        )
        return hmac.compare_digest(actual, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


def new_token(nbytes=32):
    return secrets.token_urlsafe(nbytes)


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SecretBox:
    """Fernet encryption for API tokens kept in the database."""

    def __init__(self, key_path):
        path = Path(key_path)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(Fernet.generate_key())
            os.chmod(path, 0o600)
        self._fernet = Fernet(path.read_bytes().strip())

    def encrypt(self, text):
        if text is None:
            return None
        return self._fernet.encrypt(text.encode("utf-8")).decode("ascii")

    def decrypt(self, token):
        if not token:
            return None
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            return None


def mask(secret, keep=4):
    if not secret:
        return ""
    return ("•" * 8) + secret[-keep:] if len(secret) > keep * 2 else "•" * 8
