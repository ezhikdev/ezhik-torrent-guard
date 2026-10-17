import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _paths  # noqa: F401
from ezhik_agent import paths, units, updater


class UnitTests(unittest.TestCase):
    def test_deliberate_restart_is_not_a_failure(self):
        self.assertIn("SuccessExitStatus=75", units.AGENT_UNIT)
        self.assertIn("RestartMode=direct", units.AGENT_UNIT)
        self.assertEqual(updater.RESTART_EXIT_CODE, 75)


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "releases" / "2.0.1").mkdir(parents=True)
        (root / "releases" / "2.1.2").mkdir()
        os.symlink("releases/2.1.2", root / "current")
        os.symlink("releases/2.0.1", root / "previous")
        self.root = root
        self.calls = []
        patches = [
            mock.patch.object(paths, "CURRENT_LINK", root / "current"),
            mock.patch.object(paths, "PREVIOUS_LINK", root / "previous"),
            mock.patch.object(paths, "UPDATE_FILE", root / "update.json"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def fake_run(self, exit_status):
        def run(argv, timeout=60, **_):
            self.calls.append(argv)
            out = f"{exit_status}\n" if argv[:2] == ["systemctl", "show"] else ""
            return subprocess.CompletedProcess(argv, 0, out, "")
        return run

    def test_exit_75_restarts_without_rollback(self):
        with mock.patch.object(updater, "run", self.fake_run(75)):
            self.assertEqual(updater.rollback(), 0)
        self.assertEqual(os.readlink(self.root / "current"), "releases/2.1.2")
        self.assertIn(["systemctl", "restart", paths.AGENT_UNIT], self.calls)
        self.assertFalse((self.root / "update.json").exists())

    def test_real_crash_rolls_back(self):
        (self.root / "update.json").write_text(json.dumps({"status": "restarting", "from": "2.0.1", "to": "2.1.2"}))
        with mock.patch.object(updater, "run", self.fake_run(1)):
            self.assertEqual(updater.rollback(), 0)
        self.assertEqual(Path(os.readlink(self.root / "current")).name, "2.0.1")
        self.assertEqual(json.loads((self.root / "update.json").read_text())["status"], "rolled-back")


if __name__ == "__main__":
    unittest.main()
