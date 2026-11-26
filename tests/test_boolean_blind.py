"""sqli-boolean-blind：三角关系判定 + 三次请求的执行链。

这个 oracle 的难点不在"响应不一样"，而在"不一样确实来自布尔条件"。
所以测试的重点是三种看着像、其实不是的样本：
    两份注入一模一样（参数被忽略）、假条件更像基线（分流逻辑不同）、
    真条件自己把页面打坏（差异来自崩溃而不是 SQL 语义）。
"""
from __future__ import annotations

import copy
import unittest
from typing import Any, Dict, List

from pta import vhx
from pta.critic import Critic
from pta.executor import Executor, Target
from pta.oracles import (Observation, ORACLE_REGISTRY, BooleanResponseSplit)
from pta.transport import MockRoute, MockTransport

try:                                    # Python 3.8 有，3.9+ 也保留
    from urllib.parse import unquote_plus
except ImportError:                     # pragma: no cover
    from urllib import unquote_plus

from support import WorkspaceCase

URL = "http://app.test/api/item?id=7"

BIG = b'{"items":[' + b",".join(
    b'{"id":%d,"name":"item-%d","price":%d}' % (i, i, i * 7) for i in range(1, 11)) + b"]}"
SMALL = b'{"items":[]}'


def _obs(role: str, body: bytes, status: int = 200, identity: str = "A") -> Observation:
    return Observation(
        role=role, evidence_id="%s-1" % role, identity=identity, method="GET",
        url=URL, status=status, content_type="application/json",
        body_sha256="c" * 64, body_len=len(body), body=body, headers={},
    )


def _verdict(base: bytes, true: bytes, false: bytes, **kw):
    args = BooleanResponseSplit.Args(**kw)
    return BooleanResponseSplit().run(
        [_obs("baseline", base), _obs("probe_true", true), _obs("probe_false", false)], args)


class OracleTest(unittest.TestCase):
    def test_split_confirmed(self):
        v = _verdict(BIG, BIG, SMALL)
        self.assertTrue(v.passed, v.rationale)
        self.assertGreaterEqual(v.confidence, 0.88)
        self.assertLess(v.metrics["similarity_true_false"], 0.55)
        self.assertGreaterEqual(v.metrics["similarity_true_base"], 0.90)

    def test_clean_split_gets_higher_confidence(self):
        v = _verdict(BIG, BIG, b"")
        self.assertTrue(v.passed, v.rationale)
        self.assertGreaterEqual(v.confidence, 0.93)

    def test_identical_responses_mean_param_ignored(self):
        v = _verdict(BIG, BIG, BIG)
        self.assertFalse(v.passed)
        self.assertLess(v.confidence, 0.20)
        self.assertIn("没有进入查询", v.rationale)
        self.assertGreaterEqual(v.metrics["similarity_true_false"], 0.90)

    def test_true_condition_breaking_page_is_not_evidence(self):
        # 真条件自己变成了错误页：分不清是"条件为真"还是"页面被打坏"
        v = _verdict(BIG, b'{"error":"query failed"}', BIG)
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.25)
        self.assertIn("打坏", v.rationale)

    def test_reversed_direction_is_rejected(self):
        # 假条件跟基线一模一样、真条件反而少了几行：真正的布尔注入不会长这样
        medium = BIG[: len(BIG) * 3 // 4] + b"]}"
        v = _verdict(BIG, medium, BIG)
        self.assertFalse(v.passed)
        self.assertIn("方向相反", v.rationale)

    def test_missing_role_lists_it(self):
        args = BooleanResponseSplit.Args()
        v = BooleanResponseSplit().run([_obs("baseline", BIG), _obs("probe_true", BIG)], args)
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("probe_false", v.missing_evidence)

    def test_waf_rejection_is_zero(self):
        v = BooleanResponseSplit().run(
            [_obs("baseline", BIG), _obs("probe_true", BIG, status=403),
             _obs("probe_false", SMALL, status=403)], BooleanResponseSplit.Args())
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("拒绝", v.rationale)

    def test_both_broken_is_low(self):
        v = BooleanResponseSplit().run(
            [_obs("baseline", BIG), _obs("probe_true", b"oops", status=500),
             _obs("probe_false", b"oops", status=500)], BooleanResponseSplit.Args())
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.10)


class SplitTransport(MockTransport):
    """按 query 里出现的布尔条件决定返回哪份 body。

    真实场景里服务端不会告诉你"我进 SQL 了"，只会因为结果集变化而多/少几行；
    这里用同一份可枚举大 body 模拟这个差别。
    """

    def __init__(self, mode: str = "vuln"):
        super().__init__([MockRoute("GET", "app.test", "/api/item", 200,
                                    (("Content-Type", "application/json"),), BIG)])
        self.mode = mode
        # 不要自己维护 sent：MockTransport 已经记了一份，重复 append 会让计数翻倍

    def send(self, req, timeout_s: float = 10.0):
        q = "&".join("%s=%s" % (k, v) for k, v in req.query)
        raw_q = unquote_plus(q)          # 载荷里的单引号/等号会被百分号编码
        route = self.routes[0]
        if self.mode == "waf" and "'" in raw_q:
            route.status, route.body = 403, b'{"error":"blocked by waf"}'
        elif self.mode == "ignore":
            route.status, route.body = 200, BIG
        elif "1'='2" in raw_q:
            route.status, route.body = 200, SMALL
        else:
            route.status, route.body = 200, BIG
        return super().send(req, timeout_s)


def _raw(**oracle_args: Any) -> Dict[str, Any]:
    for raw in vhx.TEMPLATES:
        if raw["id"] == "sqli-boolean-blind":
            t = copy.deepcopy(raw)
            t["oracle"]["args"].update(oracle_args)
            return t
    raise AssertionError("模板 sqli-boolean-blind 不存在")


def _tmpl(**oracle_args: Any) -> vhx.Template:
    return vhx.load(_raw(**oracle_args))


class ExecutorTest(WorkspaceCase):
    def run_tpl(self, ws):
        target = Target(url=URL, method="GET", param_path="query:id",
                        identity_baseline="A", identity_probe="A")
        return Executor(ws.probe, ws.store, "ENG-T").run(_tmpl(), target)

    def test_confirmed_on_vulnerable_param(self):
        tx = SplitTransport("vuln")
        ws = self.make_ws([], transport=tx)
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.88)
        # 三次请求：baseline / probe_true / probe_false
        self.assertEqual(len(f.evidence_ids), 3)
        self.assertEqual(len(tx.sent), 3)
        crit = Critic(ws).review_finding(f)
        self.assertEqual(crit.status, "kept", crit.blocks)

    def test_ignored_param_is_refuted(self):
        ws = self.make_ws([], transport=SplitTransport("ignore"))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertIn("没有进入查询", f.verdict["rationale"])

    def test_waf_blocks_without_false_positive(self):
        ws = self.make_ws([], transport=SplitTransport("waf"))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertEqual(f.confidence, 0.0)

    def test_all_three_evidence_rows_are_stored(self):
        ws = self.make_ws([], transport=SplitTransport("vuln"))
        f = self.run_tpl(ws)
        lens = []
        for ev_id in f.evidence_ids:
            row = ws.store.get_evidence_row(ev_id)
            self.assertEqual(row["status"], 200)
            lens.append(row["body_len"])
        # 基线/真条件是大结果集，假条件是小结果集
        self.assertEqual(sorted(lens), sorted([len(BIG), len(BIG), len(SMALL)]))


class TemplateMetaTest(unittest.TestCase):
    def test_template_is_valid_and_l1(self):
        raw = _raw()
        self.assertEqual(vhx.lint(raw), [])
        self.assertEqual(raw["side_effect_level"], "L1")
        self.assertFalse(raw["requires_approval"])
        self.assertEqual(raw["oracle"]["name"], "boolean_response_split")
        self.assertIn(raw["oracle"]["name"], ORACLE_REGISTRY)

    def test_role_hints_cover_both_conditions(self):
        roles = [h["role"] for h in _raw()["probe"]["role_hints"]]
        self.assertEqual(sorted(roles), ["probe_false", "probe_true"])
        classes = [h["payload_class"] for h in _raw()["probe"]["role_hints"]]
        self.assertEqual(sorted(classes), ["boolean_false", "boolean_true"])

    def test_budget_covers_three_requests(self):
        self.assertGreaterEqual(_raw()["budget"]["min_requests"], 3)


if __name__ == "__main__":
    unittest.main()
