"""Panel process configuration (from /etc/ezhik-guard/panel/panel.env)."""

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_file(path):
    values = {}
    try:
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[key.strip()] = value
    except OSError:
        pass
    return values


@dataclass
class Settings:
    env_file: str = "/etc/ezhik-guard/panel/panel.env"
    data_dir: Path = Path("/var/lib/ezhik-guard/panel")
    config_dir: Path = Path("/etc/ezhik-guard/panel")
    install_dir: Path = Path("/opt/ezhik-guard/panel/current")
    web_host: str = "0.0.0.0"
    web_port: int = 8443
    web_tls: bool = True
    agent_host: str = "0.0.0.0"
    agent_port: int = 8444
    public_host: str = ""
    github_repo: str = "ezhikdev/ezhik-torrent-guard"
    dns_resolvers: list = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    dev_mode: bool = False
    trusted_proxies: list = field(default_factory=list)

    @property
    def db_path(self):
        return self.data_dir / "panel.db"

    @property
    def web_dir(self):
        return self.install_dir / "web"

    @property
    def bundle_dir(self):
        return self.install_dir

    @property
    def cache_dir(self):
        return self.data_dir / "cache"

    @property
    def certs_dir(self):
        return self.data_dir / "certificates"

    @property
    def pki_dir(self):
        return self.data_dir / "pki"


def load():
    env_file = os.environ.get("EZHIK_PANEL_ENV", "/etc/ezhik-guard/panel/panel.env")
    values = {**_env_file(env_file), **{k: v for k, v in os.environ.items() if k.startswith("EZHIK_")}}
    s = Settings(env_file=env_file)

    def get(key, default=None):
        return values.get(f"EZHIK_{key}", default)

    s.data_dir = Path(get("DATA_DIR", s.data_dir))
    s.config_dir = Path(get("CONFIG_DIR", s.config_dir))
    s.install_dir = Path(get("INSTALL_DIR", s.install_dir))
    s.web_host = get("WEB_HOST", s.web_host)
    s.web_port = int(get("WEB_PORT", s.web_port))
    s.web_tls = str(get("WEB_TLS", "1")).lower() not in ("0", "false", "no")
    s.agent_host = get("AGENT_HOST", s.agent_host)
    s.agent_port = int(get("AGENT_PORT", s.agent_port))
    s.public_host = get("PUBLIC_HOST", "")
    s.github_repo = get("GITHUB_REPO", s.github_repo)
    resolvers = get("DNS_RESOLVERS")
    if resolvers:
        s.dns_resolvers = [r.strip() for r in resolvers.split(",") if r.strip()]
    s.dev_mode = str(get("DEV_MODE", "0")).lower() in ("1", "true", "yes")
    proxies = get("TRUSTED_PROXIES")
    if proxies:
        s.trusted_proxies = [p.strip() for p in proxies.split(",") if p.strip()]
    for directory in (s.data_dir, s.cache_dir, s.certs_dir):
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
    return s
