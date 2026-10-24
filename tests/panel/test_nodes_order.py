import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: F401
from ezhik_panel.db import Database
from ezhik_panel.nodes import NodeService


class NodeOrderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.nodes = NodeService(self.db, None, None, None, None, None, None)
        self.ids = [self.nodes.create(name)["id"] for name in ("alpha", "bravo", "charlie", "delta")]

    def tearDown(self):
        self.tmp.cleanup()

    def order(self):
        return [r["id"] for r in self.db.all("SELECT id FROM nodes ORDER BY sort, name COLLATE NOCASE")]

    def test_new_nodes_are_appended(self):
        self.assertEqual(self.order(), self.ids)

    def test_full_reorder(self):
        a, b, c, d = self.ids
        self.assertEqual(self.nodes.reorder([d, b, a, c]), [d, b, a, c])
        self.assertEqual(self.order(), [d, b, a, c])
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM audit WHERE action='node.reorder'"), 1)

    def test_unknown_duplicate_and_missing_ids(self):
        a, b, c, d = self.ids
        # A stale tab: knows only three nodes, repeats one and sends a deleted id.
        self.nodes.reorder([c, "gone", a, c])
        self.assertEqual(self.order(), [c, a, b, d])

    def test_same_order_is_a_no_op(self):
        self.nodes.reorder(list(self.ids))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM audit WHERE action='node.reorder'"), 0)

    def test_node_added_after_reorder_goes_last(self):
        a, b, c, d = self.ids
        self.nodes.reorder([d, c, b, a])
        e = self.nodes.create("echo")["id"]
        self.assertEqual(self.order(), [d, c, b, a, e])


if __name__ == "__main__":
    unittest.main()
