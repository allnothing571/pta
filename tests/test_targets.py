"""目标台账：别名、现场统计、别把两件事混在一起。

这一层的价值全在"它跟工作区不会对不上"：台账只存路径，域/结论数/最后活动
每次现场读。所以测试的重点是——读不到时它说什么，而不是读得到时它显得多聪明。
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from pta import targets
from pta.scope import Scope
from pta.workspace import init_workspace, open_workspace

from support import WorkspaceCase


class LedgerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pta-tgt-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self._old = os.environ.get("PTA_HOME")
        os.environ["PTA_HOME"] = os.path.join(self.tmp, "home")
        self.addCleanup(self._restore_home)

    def _restore_home(self):
        if self._old is None:
            os.environ.pop("PTA_HOME", None)
        else:
            os.environ["PTA_HOME"] = self._old

    def make_root(self, name: str) -> str:
        root = os.path.join(self.tmp, name)
        os.makedirs(root, exist_ok=True)
        return root


class RegisterTest(LedgerCase):
    def test_first_registration_becomes_the_alias(self):
        row = targets.register(self.make_root("w1"), "shop", ("app.test",))
        self.assertEqual(row["alias"], "shop")
        self.assertEqual(row["domains"], ["app.test"])

    def test_same_path_is_not_registered_twice(self):
        root = self.make_root("w1")
        targets.register(root, "shop")
        targets.register(root.rstrip(os.sep) + os.sep, "shop2")
        self.assertEqual(len(targets.entries()), 1)

    def test_alias_collision_gets_a_suffix(self):
        targets.register(self.make_root("w1"), "shop")
        row = targets.register(self.make_root("w2"), "shop")
        self.assertEqual(row["alias"], "shop-2")

    def test_explicit_alias_wins_over_engagement_id(self):
        row = targets.register(self.make_root("w1"), "shop-2026", alias="shop")
        self.assertEqual(row["alias"], "shop")

    def test_missing_directory_is_an_error(self):
        with self.assertRaises(targets.LedgerError):
            targets.register(os.path.join(self.tmp, "nope"), "x")


class LookupTest(LedgerCase):
    def test_resolve_by_alias(self):
        root = self.make_root("w1")
        targets.register(root, "shop")
        self.assertEqual(os.path.normcase(targets.resolve("shop")),
                         os.path.normcase(os.path.abspath(root)))

    def test_resolve_by_path(self):
        root = self.make_root("w1")
        targets.register(root, "shop")
        self.assertEqual(os.path.normcase(targets.resolve(root)),
                         os.path.normcase(os.path.abspath(root)))

    def test_unknown_name_resolves_to_none(self):
        self.assertIsNone(targets.resolve("nope"))

    def test_forget_removes_only_the_ledger_row(self):
        root = self.make_root("w1")
        targets.register(root, "shop")
        self.assertTrue(targets.forget("shop"))
        self.assertEqual(targets.entries(), [])
        self.assertTrue(os.path.isdir(root), "工作区目录不该被删")

    def test_forget_unknown_is_false(self):
        self.assertFalse(targets.forget("nope"))


class BrokenLedgerTest(LedgerCase):
    def test_bad_json_is_a_ledger_error_not_a_crash(self):
        path = targets.ledger_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        with self.assertRaises(targets.LedgerError):
            targets.load()

    def test_wrong_shape_is_a_ledger_error(self):
        path = targets.ledger_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"targets": "nope"}, fh)
        with self.assertRaises(targets.LedgerError):
            targets.load()

    def test_save_writes_readable_json(self):
        targets.register(self.make_root("w1"), "shop")
        with open(targets.ledger_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["version"], targets.VERSION)
        self.assertEqual(len(data["targets"]), 1)


class SummaryTest(LedgerCase):
    def test_fresh_workspace_counts_zero_and_is_not_an_error(self):
        root = self.make_root("w1")
        init_workspace(root, Scope(engagement_id="ENG-1", domains=("app.test",),
                                   allow_private=True, rate_per_host=1000.0,
                                   max_requests=100))
        row = targets.register(root, "ENG-1")
        s = targets.summary(row)
        self.assertTrue(s["exists"])
        self.assertEqual(s["findings"], 0)
        self.assertEqual(s["engagement_id"], "ENG-1")
        self.assertEqual(s["domains"], ["app.test"])
        self.assertNotIn("error", s)

    def test_counts_come_from_the_workspace_not_the_ledger(self):
        root = self.make_root("w1")
        init_workspace(root, Scope(engagement_id="ENG-1", domains=("app.test",),
                                   allow_private=True, rate_per_host=1000.0,
                                   max_requests=100))
        row = targets.register(root, "ENG-1")
        ws = open_workspace(root)
        ws.store.put_finding({
            "id": "f1", "engagement_id": "ENG-1", "template_id": "t",
            "title": "x", "status": "confirmed", "confidence": 1.0,
            "evidence_ids": [], "verdict": {},
            "created_at": "2026-11-11T00:00:00Z",
        })
        s = targets.summary(targets.get("ENG-1"))
        self.assertEqual(s["findings"], 1)
        self.assertEqual(s["confirmed"], 1)

    def test_deleted_directory_says_so(self):
        root = self.make_root("w1")
        targets.register(root, "shop")
        __import__("shutil").rmtree(root)
        s = targets.summary(targets.get("shop"))
        self.assertFalse(s["exists"])
        self.assertIn("不在了", s["error"])

    def test_broken_scope_does_not_hide_the_row(self):
        root = self.make_root("w1")
        targets.register(root, "shop")
        with open(os.path.join(root, "scope.json"), "w", encoding="utf-8") as fh:
            fh.write("{oops")
        s = targets.summary(targets.get("shop"))
        self.assertTrue(s["exists"])
        self.assertIn("scope.json", s["error"] or "")


class RenderTest(LedgerCase):
    def test_empty_ledger_explains_how_to_fill_it(self):
        text = "\n".join(targets.render([]))
        self.assertIn("pta init", text)

    def test_rows_show_alias_and_root(self):
        targets.register(self.make_root("w1"), "shop")
        text = "\n".join(targets.render(targets.listing()))
        self.assertIn("shop", text)
        self.assertIn("w1", text)
        self.assertIn("--root", text)


class ResolveArgsTest(LedgerCase):
    def _args(self, **kw):
        import argparse

        base = dict(root="shop", literal_root=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_alias_is_replaced_with_the_real_path(self):
        from pta import cli

        root = self.make_root("w1")
        targets.register(root, "shop")
        args = self._args()
        cli._resolve_root_alias(args)
        self.assertEqual(os.path.normcase(args.root), os.path.normcase(os.path.abspath(root)))

    def test_init_is_left_literal(self):
        from pta import cli

        root = self.make_root("w1")
        targets.register(root, "shop")
        args = self._args(literal_root=True)
        cli._resolve_root_alias(args)
        self.assertEqual(args.root, "shop")

    def test_unknown_name_is_left_alone(self):
        from pta import cli

        args = self._args(root="D:\\some\\new\\dir")
        cli._resolve_root_alias(args)
        self.assertEqual(args.root, "D:\\some\\new\\dir")

    def test_existing_directory_is_left_alone(self):
        from pta import cli

        root = self.make_root("w1")
        targets.register(self.make_root("w2"), "shop")
        args = self._args(root=root)
        cli._resolve_root_alias(args)
        self.assertEqual(os.path.normcase(args.root), os.path.normcase(root))


class CliTest(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self._old = os.environ.get("PTA_HOME")
        os.environ["PTA_HOME"] = os.path.join(self.tmp, "home")

        def restore():
            if self._old is None:
                os.environ.pop("PTA_HOME", None)
            else:
                os.environ["PTA_HOME"] = self._old

        self.addCleanup(restore)

    def _run(self, argv) -> int:
        import contextlib
        import io

        from pta import cli

        with contextlib.redirect_stdout(io.StringIO()):
            return cli.main(argv)

    def _init(self, name: str, alias: str) -> str:
        root = os.path.join(self.tmp, name)
        code = self._run(["init", "--root", root, "--engagement", name,
                          "--domain", "app.test", "--allow-private",
                          "--alias", alias, "--max-requests", "100"])
        self.assertEqual(code, 0)
        return root

    def test_init_prints_the_alias(self):
        root = os.path.join(self.tmp, "w1")
        code = self._run(["init", "--root", root, "--engagement", "shop",
                          "--domain", "app.test", "--allow-private",
                          "--alias", "shop2", "--max-requests", "100"])
        self.assertEqual(code, 0)
        self.assertEqual(targets.get("shop2")["root"], os.path.abspath(root))

    def test_no_register_skips_the_ledger(self):
        root = os.path.join(self.tmp, "w1")
        self._run(["init", "--root", root, "--engagement", "shop",
                   "--domain", "app.test", "--allow-private",
                   "--no-register", "--max-requests", "100"])
        self.assertEqual(targets.entries(), [])

    def test_ls_json_lists_targets(self):
        self._init("w1", "shop")
        code = self._run(["ls", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual([r["alias"] for r in targets.listing()], ["shop"])

    def test_forget_unknown_exits_one(self):
        self.assertEqual(self._run(["forget", "nope"]), 1)


if __name__ == "__main__":
    unittest.main()
