import tempfile
import time
import unittest
from pathlib import Path

import _paths  # noqa: F401
from mock_remnawave import MockRemnawave

from ezhik_panel.db import Database
from ezhik_panel.events import EventService
from ezhik_panel.remnawave import Remnawave
from ezhik_panel.sanctions import SanctionService
from ezhik_panel.security import SecretBox
from ezhik_panel.settings_service import SettingsService


class NullNotifier:
    def detection(self, *a, **k):
        pass

    def system(self, *a, **k):
        pass


class Base(unittest.TestCase):
    api = "v3"
    metadata_allowed = True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mock = MockRemnawave(api=self.api, metadata_allowed=self.metadata_allowed).start()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.settings = SettingsService(self.db, SecretBox(Path(self.tmp.name) / "k"))
        self.settings.set_remnawave(self.mock.url, "Bearer secret-token")
        self.events = EventService(self.db, self.settings, NullNotifier())
        self.svc = SanctionService(self.db, self.settings, self.events)
        self.events.sanctions = self.svc

    def tearDown(self):
        self.mock.stop()
        self.db._conn.close()
        self.tmp.cleanup()

    def run_worker(self):
        self.svc._process_due_freezes()
        self.svc._process_due_unfreezes()

    def expire(self, client):
        self.db.execute("UPDATE sanctions SET unfreeze_at=?, next_retry_at=? WHERE client_id=?",
                        (time.time() - 1, time.time() - 1, client))

    def row(self, client):
        return self.db.one("SELECT * FROM sanctions WHERE client_id=?", (client,))


class SanctionFlowV3(Base):
    def test_freeze_then_auto_unfreeze(self):
        self.mock.add_user(101)
        self.assertEqual(self.svc.queue_freeze("101", "torrent", 900), "queued")
        self.assertEqual(self.svc.queue_freeze("101", "torrent", 900), "exists")
        self.run_worker()
        self.assertEqual(self.mock.users[101]["status"], "DISABLED")
        self.assertEqual(self.row("101")["state"], "active")
        self.expire("101")
        self.run_worker()
        self.assertEqual(self.mock.users[101]["status"], "ACTIVE")
        self.assertIsNone(self.row("101"))
        paths = [p for _m, p in self.mock.calls]
        expected = "/api/users/101/actions/disable" if self.api == "v3" else \
            f"/api/users/{self.mock.users[101].get('uuid')}/actions/disable"
        self.assertIn(expected, paths)

    def test_already_disabled_user_is_never_owned(self):
        self.mock.add_user(102, status="DISABLED")
        self.svc.queue_freeze("102", "torrent", 900)
        self.run_worker()
        self.assertIsNone(self.row("102"))
        self.assertEqual(self.mock.users[102]["status"], "DISABLED")

    def test_ambiguous_500_is_recovered_as_owned(self):
        self.mock.add_user(103)
        self.mock.fail_next["disable"] = ("apply", 500)
        self.svc.queue_freeze("103", "scan", 600)
        self.run_worker()
        rec = self.row("103")
        self.assertEqual(rec["state"], "pending")
        self.assertEqual(rec["may_have_disabled"], 1)
        self.db.execute("UPDATE sanctions SET next_retry_at=0 WHERE client_id='103'")
        self.run_worker()
        self.assertEqual(self.row("103")["state"], "active")
        self.expire("103")
        self.run_worker()
        self.assertEqual(self.mock.users[103]["status"], "ACTIVE")

    def test_permanent_block_is_forgotten(self):
        self.mock.add_user(104)
        self.svc.queue_freeze("104", "scan", 0)
        self.run_worker()
        self.assertEqual(self.mock.users[104]["status"], "DISABLED")
        self.assertIsNone(self.row("104"))
        history = self.db.one("SELECT outcome FROM sanction_history WHERE client_id='104'")
        self.assertEqual(history["outcome"], "blocked-permanent")

    def test_protected_client(self):
        self.mock.add_user(105)
        self.settings.set_protection({"protected_clients": ["105"]})
        self.assertEqual(self.svc.queue_freeze("105", "torrent", 900), "protected")

    def test_hold_defers_unfreeze(self):
        self.mock.add_user(106)
        self.svc.queue_freeze("106", "torrent", 900)
        self.run_worker()
        self.svc.set_hold("106", True)
        self.expire("106")
        self.run_worker()
        self.assertEqual(self.mock.users[106]["status"], "DISABLED")
        self.svc.set_hold("106", False)
        self.expire("106")
        self.run_worker()
        self.assertEqual(self.mock.users[106]["status"], "ACTIVE")

    def test_manual_enable_clears_sanction(self):
        self.mock.add_user(107)
        self.svc.queue_freeze("107", "torrent", 900)
        self.run_worker()
        self.mock.users[107]["status"] = "ACTIVE"
        self.expire("107")
        self.run_worker()
        self.assertIsNone(self.row("107"))

    def test_release_by_admin(self):
        self.mock.add_user(108)
        self.svc.queue_freeze("108", "torrent", 900)
        self.run_worker()
        self.svc.release("108", "tester")
        self.assertEqual(self.mock.users[108]["status"], "ACTIVE")
        self.assertIsNone(self.row("108"))

    def test_unknown_user_is_dropped(self):
        self.svc.queue_freeze("999", "torrent", 900)
        self.run_worker()
        self.assertIsNone(self.row("999"))

    def test_api_detection(self):
        client = Remnawave(self.mock.url, "secret-token")
        self.assertEqual(client.detect(probe_id=1), self.api)


class SanctionFlowV3NoMetadata(SanctionFlowV3):
    metadata_allowed = False


class SanctionFlowV2(SanctionFlowV3):
    api = "v2"


class SanctionFlowV2NoMetadata(SanctionFlowV3):
    api = "v2"
    metadata_allowed = False


class PanelUpgradeTests(Base):
    api = "v2"

    def test_sanction_created_on_v2_unfreezes_after_upgrade_to_v3(self):
        self.mock.add_user(201)
        self.svc.queue_freeze("201", "torrent", 900)
        self.run_worker()
        self.assertTrue(self.row("201")["identity"].startswith("uuid:"))
        # Panel upgraded: uuid disappears, routes switch to numeric ids.
        self.mock.api = "v3"
        self.mock.users[201].pop("uuid")
        self.expire("201")
        self.run_worker()
        self.assertEqual(self.mock.users[201]["status"], "ACTIVE")
        self.assertIsNone(self.row("201"))

    def test_legacy_sanctions_adopted(self):
        user = self.mock.add_user(202, status="DISABLED")
        now = time.time()
        adopted = self.svc.adopt_legacy([{"client_id": "202", "legacy_uuid": user["uuid"],
                                          "disabled_at": now - 1000, "unfreeze_at": now - 1}], "node1")
        self.assertEqual(adopted, 1)
        self.run_worker()
        self.assertEqual(self.mock.users[202]["status"], "ACTIVE")


class PolicyTests(Base):
    def node(self, **kw):
        node = {"id": "n1", "name": "node-1", "torrent_enabled": None, "scan_enabled": None}
        node.update(kw)
        self.db.execute("INSERT OR IGNORE INTO nodes(id,name,status,created_at) VALUES('n1','node-1','active',0)")
        return node

    def event(self, etype="torrent", client="301", age=0):
        return {"id": f"e-{etype}-{client}-{age}", "type": etype, "client_id": client,
                "detected_at": time.time() - age, "data": {"reason": "first-exact-bittorrent"}}

    def test_enforce_mode_queues(self):
        self.mock.add_user(301)
        self.events.ingest(self.node(), [self.event()])
        self.assertEqual(self.row("301")["state"], "pending")

    def test_observe_mode_only_logs(self):
        self.settings.set_protection({"torrent": {"mode": "observe"}})
        self.events.ingest(self.node(), [self.event(client="302")])
        self.assertIsNone(self.row("302"))
        action = self.db.scalar("SELECT action FROM events WHERE client_id='302'")
        self.assertEqual(action, "OBSERVE")

    def test_feature_off_on_node(self):
        self.events.ingest(self.node(torrent_enabled=0), [self.event(client="303")])
        self.assertEqual(self.db.scalar("SELECT action FROM events WHERE client_id='303'"), "FEATURE_OFF")

    def test_stale_event_not_enforced(self):
        self.events.ingest(self.node(), [self.event(client="304", age=7200)])
        self.assertEqual(self.db.scalar("SELECT action FROM events WHERE client_id='304'"), "STALE")

    def test_duplicate_event_ids_are_idempotent(self):
        node = self.node()
        event = self.event(client="305")
        self.assertEqual(self.events.ingest(node, [event]), [event["id"]])
        self.assertEqual(self.events.ingest(node, [event]), [event["id"]])
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM events WHERE client_id='305'"), 1)


if __name__ == "__main__":
    unittest.main()
