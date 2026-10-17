"""Agent orchestration.

Threads:
  sync        long-poll with the panel: reports state, receives desired config
  reconciler  converges the node to the desired config (may take minutes)
  events      delivers detections from a durable outbox
  log-guard   RAM log size cap
  detector    exact attribution engine (+ its reader threads)
"""

import argparse
import json
import logging
import os
import platform
import random
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque

from . import (
    __version__, certs, legacy, logguard, paths, suricata, system, units, updater,
)
from .client import PanelClient, PanelError
from .detector import Detector, DetectorConfig
from .util import read_json, short_error, write_json

log = logging.getLogger("ezhik.agent")

SYNC_WAIT = 25
OUTBOX_LIMIT = 5000
DEFAULT_LOG_MAX = 8 * 1024 * 1024


class Agent:
    def __init__(self, config):
        self.config = config
        self.client = PanelClient(config["panel_url"], config["token"], config.get("ca_pem"), config["node_id"])
        self.state = read_json(paths.STATE_FILE, {}) or {}
        self.desired = read_json(paths.DESIRED_FILE, None)
        self.generation = self.state.get("applied_generation")
        self.stop_event = threading.Event()
        self.changed = threading.Event()
        self.lock = threading.RLock()
        self.components = {}
        self.metrics = system.Metrics()
        self.outbox = deque(maxlen=OUTBOX_LIMIT)
        self.outbox_lock = threading.Lock()
        self.outbox_ready = threading.Event()
        self.pending_acks = []
        self.diagnostics = None
        self.diagnostics_at = None
        self.update_report = updater.confirm_running()
        self.facts_cache = None
        self.wan = (None, None)
        self.detector = Detector(DetectorConfig({}), self.emit)
        self.log_guard = logguard.LogGuard(self._log_guard_settings)
        self.last_sync_ok = None
        self.sync_error = None
        self.exit_code = 0
        self.uninstalling = False
        self._load_outbox()

    # ---------------------------------------------------------- persistence

    def save_state(self):
        if self.uninstalling:
            return
        with self.lock:
            write_json(paths.STATE_FILE, self.state)

    def set_component(self, name, ok, message="", **extra):
        with self.lock:
            self.components[name] = {"ok": ok, "message": message[:600], "at": time.time(), **extra}

    def _load_outbox(self):
        try:
            with open(paths.OUTBOX_FILE, encoding="utf-8") as handle:
                for line in handle:
                    try:
                        self.outbox.append(json.loads(line))
                    except ValueError:
                        pass
        except OSError:
            pass
        if self.outbox:
            self.outbox_ready.set()

    def _persist_outbox(self):
        tmp = paths.OUTBOX_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            for item in self.outbox:
                handle.write(json.dumps(item, separators=(",", ":")) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, paths.OUTBOX_FILE)

    # --------------------------------------------------------------- events

    def emit(self, event):
        event = dict(event)
        event.setdefault("id", str(uuid.uuid4()))
        event.setdefault("detected_at", time.time())
        with self.outbox_lock:
            self.outbox.append(event)
            try:
                self._persist_outbox()
            except OSError:
                log.exception("Cannot persist event outbox")
        self.outbox_ready.set()

    def events_loop(self):
        backoff = 1
        while not self.stop_event.is_set():
            self.outbox_ready.wait(5)
            with self.outbox_lock:
                batch = list(self.outbox)[:200]
            if not batch:
                self.outbox_ready.clear()
                continue
            try:
                response = self.client.request("POST", "/agent/v1/events", {"events": batch}, timeout=30)
                accepted = set(response.get("accepted") or [])
                with self.outbox_lock:
                    kept = [e for e in self.outbox if e["id"] not in accepted]
                    self.outbox.clear()
                    self.outbox.extend(kept)
                    self._persist_outbox()
                    if not self.outbox:
                        self.outbox_ready.clear()
                backoff = 1
            except Exception as exc:
                log.warning("Event delivery failed (%d queued): %s", len(batch), short_error(exc, 200))
                self.stop_event.wait(backoff + random.random())
                backoff = min(backoff * 2, 120)

    # ----------------------------------------------------------------- sync

    def facts(self):
        osr = system.os_release()
        wan_if, wan_ip = self.wan
        return {
            "hostname": system.hostname(),
            "os": osr,
            "kernel": platform.release(),
            "arch": system.arch(),
            "python": platform.python_version(),
            "docker": system.docker_version(),
            "boot_time": system.boot_time(),
            "wan_interface": wan_if,
            "wan_ip": wan_ip,
            "container": self.detector.config.container,
            "container_state": system.container_state(self.detector.config.container),
        }

    def report(self):
        engine = (self.desired or {}).get("runtime")
        runtime = None
        if engine:
            runtime = {"engine_id": engine.get("engine_id"), "installed": suricata.is_installed(engine)}
        with self.lock:
            body = {
                "agent_version": __version__,
                "applied_generation": self.generation,
                "facts": self.facts_cache,
                "metrics": self.metrics.sample(self.wan[0]),
                "detector": self.detector.snapshot(),
                "components": dict(self.components),
                "cert": self.state.get("cert"),
                "runtime": runtime,
                "update": self.state.get("update"),
                "legacy": self.state.get("legacy"),
                "outbox": len(self.outbox),
                "acks": list(self.pending_acks),
                "wait": SYNC_WAIT,
            }
            if self.update_report:
                body["update_report"] = self.update_report
            if self.diagnostics is not None:
                body["diagnostics"] = self.diagnostics
                body["diagnostics_at"] = self.diagnostics_at
        return body

    def sync_loop(self):
        backoff = 1
        facts_at = 0
        while not self.stop_event.is_set():
            if time.time() - facts_at > 300 or self.facts_cache is None:
                try:
                    self.facts_cache = self.facts()
                except Exception:
                    log.exception("Cannot collect host facts")
                facts_at = time.time()
            body = self.report()
            sent_acks = body["acks"]
            try:
                response = self.client.request("POST", "/agent/v1/sync", body, timeout=SYNC_WAIT + 20)
                self.last_sync_ok = time.time()
                self.sync_error = None
                with self.lock:
                    self.pending_acks = [a for a in self.pending_acks if a not in sent_acks]
                    if body.get("update_report"):
                        self.update_report = None
                        updater.acknowledge()
                    if "diagnostics" in body:
                        self.diagnostics = None
                self.handle_response(response)
                backoff = 1
            except PanelError as exc:
                self.sync_error = short_error(exc, 200)
                if exc.status in (401, 403):
                    log.error("Panel rejected this node's credentials (%s); retrying slowly", exc)
                    self.stop_event.wait(60)
                    continue
                if exc.status == 410:
                    log.error("Node was deleted in the panel; uninstalling")
                    self.uninstall()
                    return
                log.warning("Sync failed: %s", exc)
                self.stop_event.wait(backoff + random.random())
                backoff = min(backoff * 2, 60)
            except Exception as exc:
                self.sync_error = short_error(exc, 200)
                log.warning("Panel unreachable: %s", short_error(exc, 200))
                self.stop_event.wait(backoff + random.random())
                backoff = min(backoff * 2, 60)

    def handle_response(self, response):
        config = response.get("config")
        generation = response.get("generation")
        if config is not None and (generation != self.state.get("desired_generation") or self.desired is None):
            with self.lock:
                self.desired = config
            write_json(paths.DESIRED_FILE, config)
            self.state["desired_generation"] = generation
            self.changed.set()
        for command in response.get("commands") or []:
            threading.Thread(target=self.run_command, args=(command,), daemon=True).start()

    # ------------------------------------------------------------ commands

    def run_command(self, command):
        kind, cid = command.get("type"), command.get("id")
        try:
            if kind == "diagnose":
                self.run_diagnostics()
            elif kind == "resync":
                self.state.pop("suricata_fingerprint", None)
                self.state.pop("cert", None)
                self.changed.set()
            elif kind == "restart_detector":
                self.detector.stop()
                self.detector.start()
            elif kind == "restart_suricata":
                system.systemctl("restart", paths.SURICATA_UNIT)
            elif kind == "uninstall":
                with self.lock:
                    self.pending_acks.append(cid)
                self.uninstall()
                return
            elif kind == "restart_agent":
                with self.lock:
                    self.pending_acks.append(cid)
                time.sleep(SYNC_WAIT + 5)
                self.request_restart()
                return
        except Exception as exc:
            log.exception("Command %s failed", kind)
            self.set_component("command", False, f"{kind}: {short_error(exc)}")
        with self.lock:
            self.pending_acks.append(cid)

    # ----------------------------------------------------------- reconcile

    def reconcile_loop(self):
        if self.desired is not None:
            self.changed.set()
        while not self.stop_event.is_set():
            triggered = self.changed.wait(60)
            self.changed.clear()
            if self.desired is None:
                continue
            try:
                self.reconcile(self.desired, triggered)
            except Exception:
                log.exception("Reconcile failed")

    def reconcile(self, desired, triggered):
        generation = self.state.get("desired_generation")
        self.step("legacy", lambda: self.reconcile_legacy(desired))
        self.step("network", lambda: self.reconcile_network(desired))
        self.step("suricata", lambda: self.reconcile_suricata(desired))
        self.step("detector", lambda: self.reconcile_detector(desired))
        self.step("certificate", lambda: self.reconcile_cert(desired))
        self.step("agent_update", lambda: self.reconcile_update(desired))
        if triggered:
            with self.lock:
                self.generation = generation
                self.state["applied_generation"] = generation
            self.save_state()
            # Fresh diagnostics reflect what was just applied.
            self.run_diagnostics()

    def step(self, name, func):
        try:
            message = func() or ""
            if message is not None:
                self.set_component(name, True, message)
        except Exception as exc:
            log.error("%s: %s", name, short_error(exc))
            self.set_component(name, False, short_error(exc))

    def reconcile_legacy(self, desired):
        found = legacy.detect()
        if not found["present"]:
            self.state["legacy"] = {"present": False, "report": (self.state.get("legacy") or {}).get("report")}
            return "no legacy components"
        if not desired.get("remove_legacy", True):
            self.state["legacy"] = {"present": True, **found}
            return "legacy present; removal disabled"
        sanctions = legacy.read_sanctions()
        settings = legacy.read_settings()
        self.client.request("POST", "/agent/v1/legacy", {
            "detected": found, "sanctions": sanctions, "settings": settings,
        }, timeout=60)
        report = legacy.remove(container=self.detector.config.container)
        self.state["legacy"] = {"present": False, "report": report, "removed_version": found.get("version")}
        self.save_state()
        return f"legacy Torrent Guard {found.get('version') or ''} removed; {len(sanctions)} sanctions handed over"

    def reconcile_network(self, desired):
        wan_if, wan_ip = system.wan_route()
        wan_if = desired.get("interface") or wan_if
        wan_ip = desired.get("wan_ip") or wan_ip
        if not wan_if or not wan_ip:
            raise RuntimeError("cannot detect the WAN interface/IPv4 (ip route get 1.1.1.1)")
        if desired.get("wan_ip") and not system.interface_has_ip(wan_if, wan_ip):
            raise RuntimeError(f"{wan_ip} is not assigned to {wan_if}")
        if (wan_if, wan_ip) != self.wan:
            self.wan = (wan_if, wan_ip)
            self.facts_cache = None
        return f"{wan_if} / {wan_ip}"

    def reconcile_suricata(self, desired):
        detector_cfg = desired.get("detector") or {}
        torrent = (detector_cfg.get("torrent") or {}).get("enabled")
        engine = desired.get("runtime")
        if not torrent:
            if system.unit_active(paths.SURICATA_UNIT):
                suricata.stop()
            return "disabled (torrent protection is off)"
        if not engine:
            raise RuntimeError("panel did not provide a runtime for this OS")
        system.ensure_packages(["zstd", "python3-yaml", "ca-certificates"])
        if not suricata.is_installed(engine):
            osv = system.os_release()["version"]
            archive = paths.DOWNLOAD_DIR / engine["asset"]
            self.set_component("suricata", True, "downloading runtime", progress="downloading")
            self.client.download(engine["url"], archive, engine["sha256"], timeout=900)
            suricata.install(engine, archive, osv,
                             lambda stage: self.set_component("suricata", True, stage, progress=stage))
            archive.unlink(missing_ok=True)
            self.state.pop("suricata_fingerprint", None)
        wan_if, wan_ip = self.wan
        suricata.ensure_running(engine, wan_if, wan_ip, self.state)
        self.save_state()
        return f"active ({engine['engine_id']})"

    def reconcile_detector(self, desired):
        raw = dict(desired.get("detector") or {})
        raw["local_ip"] = self.wan[1]
        cfg = DetectorConfig(raw)
        if cfg.any_enabled and not system.docker_available():
            raise RuntimeError("Docker is not available; cannot read Xray logs")
        if cfg.any_enabled and not system.container_state(cfg.container):
            raise RuntimeError(f"container {cfg.container} not found")
        self.detector.update_config(cfg)
        if not cfg.any_enabled:
            self.detector.stop()
            return "idle (all protections disabled)"
        if not system.xray_logs_present(cfg.container):
            raise RuntimeError("Xray RAM logs /dev/shm/xray-access.log and xray-info.log are missing in the container")
        return "running"

    def reconcile_cert(self, desired):
        cert = desired.get("cert")
        target = desired.get("cert_target") or {}
        current = self.state.get("cert") or {}
        if not cert:
            if desired.get("cert_remove") and current.get("id"):
                certs.remove(target)
                self.state["cert"] = None
                self.save_state()
                return "certificate removed from node"
            if current.get("id"):
                self.state["cert"] = None
                self.save_state()
            return None if not current else "not managed"
        want = (cert["id"], cert["version"], json.dumps(target, sort_keys=True))
        have = (current.get("id"), current.get("version"), current.get("target_key"))
        if want == have and not current.get("error"):
            if certs.restore_container_copy(target):
                log.info("Restored certificate inside recreated container")
            return f"{cert.get('name') or cert['id']} v{cert['version']}"
        bundle = self.client.request("GET", "/agent/v1/certificate", timeout=60)
        if bundle.get("version") != cert["version"] or bundle.get("certificate_id") != cert["id"]:
            raise RuntimeError("panel returned a different certificate version; will retry")
        try:
            not_after = certs.install(bundle, target)
        except Exception as exc:
            self.state["cert"] = {"id": cert["id"], "version": cert["version"], "error": short_error(exc),
                                  "target_key": want[2]}
            self.save_state()
            raise
        self.state["cert"] = {
            "id": cert["id"], "version": cert["version"], "not_after": not_after,
            "fingerprint": certs.installed_fingerprint(target), "installed_at": time.time(),
            "target_key": want[2], "error": None,
        }
        self.save_state()
        return f"installed v{cert['version']}"

    def reconcile_update(self, desired):
        wanted = (desired.get("agent") or {})
        version = wanted.get("version")
        if not version or version == __version__:
            if self.state.get("update", {}).get("state") not in (None, "idle"):
                self.state["update"] = {"state": "idle", "version": __version__}
            return None
        failed = self.state.get("update") or {}
        if failed.get("state") == "failed" and failed.get("version") == version and time.time() - failed.get("at", 0) < 600:
            raise RuntimeError(f"update to {version} failed recently: {failed.get('error')}")
        self.state["update"] = {"state": "downloading", "version": version, "at": time.time()}
        try:
            archive = paths.DOWNLOAD_DIR / f"agent-{version}.tar.gz"
            self.client.download(wanted["url"], archive, wanted["sha256"], timeout=300)
            self.state["update"]["state"] = "installing"
            release = updater.prepare_release(archive, version)
            archive.unlink(missing_ok=True)
            updater.activate(release, version)
            updater.prune_releases()
        except Exception as exc:
            self.state["update"] = {"state": "failed", "version": version, "error": short_error(exc), "at": time.time()}
            self.save_state()
            raise
        self.state["update"] = {"state": "restarting", "version": version, "at": time.time()}
        self.save_state()
        # Give the sync loop a moment to report "restarting".
        time.sleep(2)
        self.request_restart()
        return f"activated {version}; restarting"

    # --------------------------------------------------------- diagnostics

    def run_diagnostics(self):
        from .diagnostics import run_all

        result = run_all(self)
        with self.lock:
            self.diagnostics = result
            self.diagnostics_at = time.time()

    # ------------------------------------------------------------ lifecycle

    def _log_guard_settings(self):
        desired = self.desired or {}
        return (
            self.detector.config.container,
            int(desired.get("log_max_bytes") or DEFAULT_LOG_MAX),
            self.detector.running,
        )

    def run(self):
        paths.ensure_private_dirs()
        try:
            units.sync()
        except Exception:
            log.exception("Cannot refresh systemd units")
        signal.signal(signal.SIGTERM, lambda *_: self.stop_event.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop_event.set())
        log.info("Ezhik Guard agent %s starting (node %s, panel %s)", __version__, self.config["node_id"], self.config["panel_url"])
        if self.desired:
            try:
                self.reconcile_network(self.desired)
            except Exception:
                pass
        threading.Thread(target=self.sync_loop, name="sync", daemon=True).start()
        threading.Thread(target=self.events_loop, name="events", daemon=True).start()
        threading.Thread(target=self.reconcile_loop, name="reconciler", daemon=True).start()
        self.log_guard.start()
        threading.Thread(target=self.run_diagnostics, name="diagnostics-initial", daemon=True).start()
        last_diag = time.time()
        while not self.stop_event.wait(5):
            if time.time() - last_diag > 600:
                threading.Thread(target=self.run_diagnostics, daemon=True).start()
                last_diag = time.time()
        self.shutdown()

    def request_restart(self):
        """Exit through the main thread; systemd starts the current release."""
        self.exit_code = updater.RESTART_EXIT_CODE
        self.stop_event.set()

    def shutdown(self):
        self.stop_event.set()
        self.log_guard.stop()
        try:
            self.detector.stop()
        except Exception:
            pass
        if not self.uninstalling:
            try:
                self.save_state()
            except Exception:
                pass

    def uninstall(self):
        from .uninstall import uninstall_detached

        with self.lock:
            if self.uninstalling:
                return
            self.uninstalling = True
        try:
            self.client.request("POST", "/agent/v1/goodbye", {}, timeout=15)
        except Exception:
            pass
        # Launch the detached remover first: it stops this service itself.
        uninstall_detached()
        self.exit_code = 0
        self.stop_event.set()


# ------------------------------------------------------------------ CLI


def load_config():
    cfg = read_json(paths.CONFIG_FILE)
    if not cfg or not all(cfg.get(k) for k in ("panel_url", "node_id", "token")):
        raise SystemExit(f"{paths.CONFIG_FILE} is missing or incomplete; run the install command from the panel")
    return cfg


def cmd_register(args):
    ca_pem = open(args.ca_file, encoding="ascii").read() if args.ca_file else None
    existing = read_json(paths.CONFIG_FILE)
    if existing and existing.get("node_id") and not args.force:
        print(f"Node already registered as {existing['node_id']}; keeping credentials.")
        return 0
    client = PanelClient(args.panel, ca_pem=ca_pem)
    osr = system.os_release()
    wan_if, wan_ip = system.wan_route()
    response = client.request("POST", "/agent/v1/register", {
        "install_token": args.token,
        "hostname": system.hostname(),
        "name": args.name,
        "os": osr,
        "arch": system.arch(),
        "agent_version": __version__,
        "wan_interface": wan_if,
        "wan_ip": wan_ip,
    })
    paths.ensure_private_dirs()
    write_json(paths.CONFIG_FILE, {
        "panel_url": response.get("panel_url") or args.panel,
        "node_id": response["node_id"],
        "token": response["node_token"],
        "ca_pem": ca_pem,
        "registered_at": time.time(),
    })
    print(f"Registered as node {response['node_id']} ({response.get('name') or ''})")
    return 0


def cmd_status(_args):
    state = read_json(paths.STATE_FILE, {}) or {}
    desired = read_json(paths.DESIRED_FILE, {}) or {}
    print(json.dumps({"version": __version__, "state": state, "desired_generation": state.get("desired_generation"),
                      "detector": desired.get("detector")}, indent=2, ensure_ascii=False))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ezhik-guard-agent")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run")
    reg = sub.add_parser("register")
    reg.add_argument("--panel", required=True)
    reg.add_argument("--token", required=True)
    reg.add_argument("--ca-file")
    reg.add_argument("--name")
    reg.add_argument("--force", action="store_true")
    sub.add_parser("status")
    sub.add_parser("rollback")
    sub.add_parser("uninstall")
    sub.add_parser("version")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    if args.command == "register":
        return cmd_register(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "rollback":
        return updater.rollback()
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "uninstall":
        from .uninstall import uninstall_now

        return uninstall_now()
    agent = Agent(load_config())
    agent.run()
    return agent.exit_code


__all__ = ["main", "Agent", "subprocess"]
