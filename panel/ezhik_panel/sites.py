"""Stub websites (ZIP upload, versions, preview, bundles for nodes)."""

import base64
import hashlib
import hmac
import io
import json
import re
import shutil
import stat
import tarfile
import time
import uuid
import zipfile
from pathlib import PurePosixPath

ALLOWED_EXT = {
    "html", "htm", "css", "js", "mjs", "json", "txt", "xml", "svg", "png", "jpg", "jpeg", "gif", "webp", "avif",
    "ico", "bmp", "woff", "woff2", "ttf", "otf", "eot", "map", "mp4", "webm", "ogg", "mp3", "wav", "pdf",
    "webmanifest", "csv", "md", "wasm",
}
MAX_FILES, MAX_TOTAL, MAX_FILE = 3000, 150 << 20, 50 << 20
PREVIEW_TTL = 6 * 3600

# Same page the agent installs when no site is assigned.
DEFAULT_PREVIEW_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title><style>body{font-family:system-ui,sans-serif;margin:0;display:grid;place-items:center;
min-height:100vh;background:#f4f5f7;color:#222}main{text-align:center}h1{font-weight:600}</style></head>
<body><main><h1>Site is under construction</h1><p>Please check back later.</p></main></body></html>
"""


class SiteError(ValueError):
    pass


def safe_name(name):
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise SiteError(f"абсолютный путь в архиве: {name}")
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise SiteError(f"путь с «..» в архиве: {name}")
    if any(p.startswith(".") and p not in (".well-known",) for p in parts) or (parts and parts[0] == "__MACOSX"):
        return None  # hidden files, macOS metadata
    return "/".join(parts)


def extract_zip(data, target):
    """Safely unpack a ZIP into `target`. Returns (files, size, skipped)."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise SiteError("файл не является ZIP-архивом")
    entries = [i for i in archive.infolist() if not i.is_dir()]
    if not entries:
        raise SiteError("архив пуст")
    if len(entries) > MAX_FILES:
        raise SiteError(f"слишком много файлов (> {MAX_FILES})")
    total = sum(i.file_size for i in entries)
    if total > MAX_TOTAL:
        raise SiteError("распакованный сайт больше 150 МБ")
    names, skipped = [], []
    for info in entries:
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise SiteError(f"символические ссылки не допускаются: {info.filename}")
        if info.file_size > MAX_FILE:
            raise SiteError(f"файл больше 50 МБ: {info.filename}")
        name = safe_name(info.filename)
        if not name:
            continue
        ext = name.rsplit(".", 1)[-1].lower() if "." in name.rsplit("/", 1)[-1] else ""
        if ext not in ALLOWED_EXT:
            skipped.append(name)
            continue
        names.append((info, name))
    if not names:
        raise SiteError("в архиве нет файлов сайта")
    # A ZIP of a folder: strip the single common top-level directory.
    tops = {n.split("/", 1)[0] for _, n in names}
    prefix = ""
    if len(tops) == 1 and all("/" in n for _, n in names):
        prefix = tops.pop() + "/"
    target.mkdir(parents=True, exist_ok=True)
    count = 0
    for info, name in names:
        rel = name[len(prefix):] if prefix and name.startswith(prefix) else name
        dest = target / rel
        if target.resolve() not in dest.resolve().parents:
            raise SiteError(f"недопустимый путь: {name}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as src, open(dest, "wb") as out:
            remaining = MAX_FILE + 1
            while True:
                chunk = src.read(1 << 16)
                if not chunk:
                    break
                remaining -= len(chunk)
                if remaining < 0:  # header lied about the size (zip bomb)
                    raise SiteError(f"файл больше заявленного: {name}")
                out.write(chunk)
        count += 1
    if not (target / "index.html").exists():
        raise SiteError("в корне сайта нет index.html")
    return count, total, skipped


class SiteService:
    def __init__(self, db, config, secret):
        self.db = db
        self.root = config.data_dir / "sites"
        self.root.mkdir(parents=True, exist_ok=True)
        self.secret = secret

    # ------------------------------------------------------------ queries

    def list(self):
        sites = self.db.all("SELECT * FROM sites ORDER BY is_default DESC, name")
        for site in sites:
            site["versions"] = self.db.all("SELECT * FROM site_versions WHERE site_id=? ORDER BY created_at DESC",
                                           (site["id"],))
            site["nodes"] = self.db.all("SELECT id, name FROM nodes WHERE site_id=? ORDER BY name", (site["id"],))
        return sites

    def get(self, site_id):
        site = self.db.one("SELECT * FROM sites WHERE id=?", (site_id,))
        if not site:
            raise LookupError("Сайт не найден")
        return site

    def default(self):
        return self.db.one("SELECT * FROM sites WHERE is_default=1")

    def effective_for(self, node):
        """(site row, version) a node should serve, or (None, None) for the built-in page."""
        site_id = node.get("site_id")
        if site_id == "builtin":
            return None, None
        site = self.db.one("SELECT * FROM sites WHERE id=?", (site_id,)) if site_id else self.default()
        if not site or not site["current_version"]:
            return None, None
        return site, site["current_version"]

    # ------------------------------------------------------------- upload

    def upload(self, data, name=None, site_id=None, note=None, actor="admin"):
        now = time.time()
        if site_id:
            site = self.get(site_id)
        else:
            site_id = uuid.uuid4().hex[:10]
            is_default = 0 if self.default() else 1
            self.db.execute("INSERT INTO sites(id,name,is_default,created_at,updated_at) VALUES(?,?,?,?,?)",
                            (site_id, (name or "Сайт")[:60], is_default, now, now))
            site = self.get(site_id)
        # Versions are unique across all sites: agents keep releases by version
        # name, and an existing version directory must never be overwritten.
        number = int(now)
        while self.db.scalar("SELECT 1 FROM site_versions WHERE version=?", (str(number),)) or \
                (self.root / site_id / str(number)).exists():
            number += 1
        version = str(number)
        target = self.root / site_id / version
        try:
            files, size, skipped = extract_zip(data, target)
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            if not self.db.scalar("SELECT COUNT(*) FROM site_versions WHERE site_id=?", (site_id,)):
                self.db.execute("DELETE FROM sites WHERE id=?", (site_id,))
            raise
        sha = self._bundle(site_id, version)
        self.db.execute("INSERT INTO site_versions(site_id,version,files,size,sha256,note,created_at) VALUES(?,?,?,?,?,?,?)",
                        (site_id, version, files, size, sha, (note or "")[:200], now))
        self.db.execute("UPDATE sites SET draft_version=?, updated_at=? WHERE id=?", (version, now, site_id))
        if not site["current_version"]:
            # First version is published immediately.
            self.publish(site_id, version, actor)
        self.db.audit(actor, "site.upload", site_id, {"version": version, "files": files, "skipped": len(skipped)})
        return {"site": self.get(site_id), "version": version, "files": files, "skipped": skipped[:50]}

    def _bundle(self, site_id, version):
        source = self.root / site_id / version
        path = self.root / site_id / f"{version}.tar.gz"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for file in sorted(source.rglob("*")):
                if file.is_file():
                    info = archive.gettarinfo(str(file), file.relative_to(source).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mode = 0o644
                    with open(file, "rb") as handle:
                        archive.addfile(info, handle)
        path.write_bytes(buffer.getvalue())
        return hashlib.sha256(buffer.getvalue()).hexdigest()

    def bundle_path(self, site_id, version):
        path = self.root / site_id / f"{version}.tar.gz"
        if not path.exists():
            raise LookupError("версия сайта не найдена")
        return path

    def publish(self, site_id, version, actor="admin"):
        if not self.db.scalar("SELECT 1 FROM site_versions WHERE site_id=? AND version=?", (site_id, version)):
            raise LookupError("версия не найдена")
        self.db.execute("UPDATE sites SET current_version=?, draft_version=CASE WHEN draft_version=? THEN NULL "
                        "ELSE draft_version END, updated_at=? WHERE id=?", (version, version, time.time(), site_id))
        self.db.audit(actor, "site.publish", site_id, {"version": version})

    def update(self, site_id, name=None, is_default=None, actor="admin"):
        self.get(site_id)
        if name:
            self.db.execute("UPDATE sites SET name=? WHERE id=?", (name[:60], site_id))
        if is_default:
            self.db.execute("UPDATE sites SET is_default=CASE WHEN id=? THEN 1 ELSE 0 END", (site_id,))
        self.db.audit(actor, "site.update", site_id)

    def delete(self, site_id, actor="admin"):
        site = self.get(site_id)
        if self.db.scalar("SELECT COUNT(*) FROM nodes WHERE site_id=?", (site_id,)):
            raise SiteError("Сайт назначен нодам — сначала назначьте им другой")
        self.db.execute("DELETE FROM sites WHERE id=?", (site_id,))
        shutil.rmtree(self.root / site_id, ignore_errors=True)
        if site["is_default"]:
            other = self.db.one("SELECT id FROM sites ORDER BY created_at LIMIT 1")
            if other:
                self.db.execute("UPDATE sites SET is_default=1 WHERE id=?", (other["id"],))
        self.db.audit(actor, "site.delete", site_id)

    def delete_version(self, site_id, version, actor="admin"):
        site = self.get(site_id)
        if site["current_version"] == version:
            raise SiteError("Нельзя удалить опубликованную версию")
        self.db.execute("DELETE FROM site_versions WHERE site_id=? AND version=?", (site_id, version))
        if site["draft_version"] == version:
            self.db.execute("UPDATE sites SET draft_version=NULL WHERE id=?", (site_id,))
        shutil.rmtree(self.root / site_id / version, ignore_errors=True)
        (self.root / site_id / f"{version}.tar.gz").unlink(missing_ok=True)

    # ------------------------------------------------------------ preview

    def preview_token(self, site_id, version):
        expires = int(time.time()) + PREVIEW_TTL
        payload = f"{site_id}:{version}:{expires}"
        sig = hmac.new(self.secret, payload.encode(), hashlib.sha256).digest()[:16]
        return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=") + "." + \
            base64.urlsafe_b64encode(sig).decode().rstrip("=")

    def resolve_token(self, token):
        try:
            body, sig = token.split(".", 1)
            payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode()
            expected = hmac.new(self.secret, payload.encode(), hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(expected, base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))):
                return None
            site_id, version, expires = payload.split(":")
            if int(expires) < time.time():
                return None
        except (ValueError, UnicodeDecodeError):
            return None
        directory = self.root / site_id / version
        return directory if directory.is_dir() else None


# Root-relative URLs ("/css/a.css") would hit the panel itself in preview;
# rewrite them to the preview prefix in HTML attributes and CSS.
_ATTR_RE = re.compile(r'(\b(?:src|href|action|poster|data|formaction)\s*=\s*)(["\'])/(?!/)', re.I)
_SRCSET_RE = re.compile(r'(\bsrcset\s*=\s*)(["\'])([^"\']*)\2', re.I)
_CSS_URL_RE = re.compile(r'(url\(\s*["\']?)/(?!/)', re.I)
_CSS_IMPORT_RE = re.compile(r'(@import\s+["\'])/(?!/)', re.I)
_JS_IMPORT_RE = re.compile(r'(\bfrom\s*|\bimport\s*\(?\s*)(["\'])/(?!/)')
_HEAD_RE = re.compile(r"<head\b[^>]*>", re.I)

# Root-relative URLs built by scripts at runtime (fetch, XHR, history, DOM
# properties, dynamically created links) are prefixed by this small shim,
# injected first into every previewed HTML page.
_SHIM = """<script>(function(){var P=%s;function f(u){return typeof u==='string'&&u.charAt(0)==='/'&&u.charAt(1)!=='/'&&u.indexOf(P+'/')!==0&&u!==P?P+u:u}
var F=window.fetch;if(F)window.fetch=function(i,o){return F.call(this,typeof i==='string'?f(i):i,o)};
var X=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=f(u);return X.apply(this,arguments)};
['pushState','replaceState'].forEach(function(k){var h=history[k];history[k]=function(s,t,u){return h.call(this,s,t,u==null?u:f(String(u)))}});
var W=window.open;window.open=function(u){arguments[0]=f(u);return W.apply(this,arguments)};
var A=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if(/^(src|href|action|poster|formaction)$/i.test(n))v=f(String(v));return A.call(this,n,v)};
[[HTMLImageElement,'src'],[HTMLScriptElement,'src'],[HTMLLinkElement,'href'],[HTMLAnchorElement,'href'],[HTMLIFrameElement,'src'],[HTMLSourceElement,'src'],[HTMLMediaElement,'src'],[HTMLFormElement,'action']].forEach(function(p){var d=Object.getOwnPropertyDescriptor(p[0].prototype,p[1]);if(d&&d.set)Object.defineProperty(p[0].prototype,p[1],{get:d.get,set:function(v){d.set.call(this,f(String(v)))},configurable:true})});
document.addEventListener('click',function(e){var a=e.target&&e.target.closest&&e.target.closest('a[href]');if(a){var h=a.getAttribute('href');if(f(h)!==h)a.setAttribute('href',h)}},true);
})();</script>"""


def rewrite(content, kind, prefix):
    text = content.decode("utf-8", errors="replace")
    if kind == "html":
        text = _ATTR_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{prefix}/", text)
        text = _SRCSET_RE.sub(lambda m: m.group(1) + m.group(2) + ", ".join(
            (prefix + p.strip() if p.strip().startswith("/") and not p.strip().startswith("//") else p.strip())
            for p in m.group(3).split(",")) + m.group(2), text)
        text = re.sub(r"(<style[^>]*>)(.*?)(</style>)", lambda m: m.group(1) + rewrite(m.group(2).encode(), "css", prefix)
                      + m.group(3), text, flags=re.S | re.I)
        text = re.sub(r'(\bstyle\s*=\s*")([^"]*)(")', lambda m: m.group(1) + rewrite(m.group(2).encode(), "css", prefix)
                      + m.group(3), text, flags=re.I)
        shim = _SHIM % json.dumps(prefix)
        head = _HEAD_RE.search(text)
        text = text[:head.end()] + shim + text[head.end():] if head else shim + text
    elif kind == "js":
        text = _JS_IMPORT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{prefix}/", text)
    else:
        text = _CSS_URL_RE.sub(lambda m: m.group(1) + prefix + "/", text)
        text = _CSS_IMPORT_RE.sub(lambda m: m.group(1) + prefix + "/", text)
    return text


def default_json(value):
    return json.dumps(value, ensure_ascii=False)
