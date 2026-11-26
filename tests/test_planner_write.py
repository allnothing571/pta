"""写入型越权自动候选（第 5 项）。

规则只有一条契约：**只有页面自己用写方法打过这个地址，才自动提"改写对象"**。
GET 上的 `name`/`role` 是查询条件，拿它去试写等于凭空造候选——这类噪声会让
操作者开始忽略 Planner 的建议，比漏报更糟。
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta import vhx  # noqa: E402
from pta.planner import Asset, PlannerState, heuristic_candidates  # noqa: E402


def state(*assets):
    return PlannerState(engagement_id="ENG-PW", domains=("app.test",),
                        assets=list(assets), findings=[], budget={"used": 0, "max": 100},
                        templates=list(vhx.TEMPLATES))


def find(cands, tid):
    return [c for c in cands if c.template_id == tid]


class WriteCandidateTest(unittest.TestCase):
    def test_post_without_known_body_proposes_generic_write(self):
        cands = heuristic_candidates(state(
            Asset(url="http://app.test/api/v2/profile", method="POST", status=201,
                  content_type="application/json")))
        write = find(cands, "idor-write-object")
        self.assertEqual(len(write), 1)
        self.assertEqual(write[0].method, "POST")
        self.assertEqual(write[0].param_path, "body:*")
        self.assertIn("harvest", write[0].rationale)

    def test_get_never_proposes_write(self):
        cands = heuristic_candidates(state(
            Asset(url="http://app.test/api/profile", method="GET", status=200,
                  content_type="application/json")))
        self.assertEqual(find(cands, "idor-write-object"), [])

    def test_known_body_fields_win_over_generic(self):
        # 已经知道请求体长什么样，就别再出"通用写一次"的重复候选
        cands = heuristic_candidates(state(
            Asset(url="http://app.test/api/users/3", method="PUT", status=200,
                  content_type="application/json", body_params=("name", "email"))))
        self.assertEqual([c for c in cands if c.param_path == "body:*"], [])
        # 具体字段各自出候选，且继承 PUT
        named = [c for c in cands if c.param_path in ("body:name", "body:email")]
        self.assertEqual(len(named), 2)
        self.assertTrue(all(c.method == "PUT" for c in named))

    def test_get_on_body_fields_is_not_a_write_candidate(self):
        cands = heuristic_candidates(state(
            Asset(url="http://app.test/api/search", method="GET", status=200,
                  content_type="application/json", body_params=("role", "name"))))
        self.assertEqual(find(cands, "mass-assignment-privilege"), [])
        self.assertEqual([c for c in cands if c.param_path.startswith("body:")], [])

    def test_patch_is_a_write_method(self):
        cands = heuristic_candidates(state(
            Asset(url="http://app.test/api/v2/orders/9", method="PATCH", status=204,
                  content_type="application/json")))
        write = find(cands, "idor-write-object")
        self.assertEqual(len(write), 1)
        self.assertEqual(write[0].method, "PATCH")

    def test_non_api_write_skipped(self):
        # 表单提交页（text/html）不改对象：写上去只会得到 200 HTML
        cands = heuristic_candidates(state(
            Asset(url="http://app.test/login", method="POST", status=200,
                  content_type="text/html")))
        self.assertEqual(find(cands, "idor-write-object"), [])

    def test_candidate_keeps_method_into_target(self):
        cands = heuristic_candidates(state(
            Asset(url="http://app.test/api/v2/profile", method="POST", status=201,
                  content_type="application/json")))
        target = find(cands, "idor-write-object")[0].to_target()
        self.assertEqual(target.method, "POST")
        self.assertEqual(target.param_path, "body:*")


if __name__ == "__main__":
    unittest.main()
