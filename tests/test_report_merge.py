"""报告增强（第 9 项）：单文件 HTML + 多 engagement 合并。

两条都不能靠"看起来像"验收：
- HTML 必须是单文件（没有任何外部资源），否则"发给别人就能看"不成立；
- 合并必须逐条标明轮次，否则两轮同名模板会被读成"重复上报"。
"""
from __future__ import annotations

import json
import os
import unittest

from pta.probe import ProbeRequest
from pta.report import ReportOptions, export_report

from support import OBJECT_BODY, WorkspaceCase

NOW = "2026-03-04T05:06:07Z"
ENG = "ENG-T"
ENG2 = "ENG-T2"


class ReportMergeTest(WorkspaceCase):
    def ws_with(self):
        from pta.transport import MockRoute
        routes = [MockRoute("GET", "app.test", "/api/users/1", 200,
                            (("Content-Type", "application/json"),), OBJECT_BODY)]
        return self.make_ws(routes)

    def seed(self, ws, identity="A", label="baseline-A"):
        res = ws.probe.run(ProbeRequest(action_id="a1", url="http://app.test/api/users/1",
                                        identity=identity, label=label))
        self.assertEqual(res.status, "ok")
        return res.evidence_id

    def add_finding(self, ws, evidence_ids, eng=ENG, status="confirmed", confidence=0.99,
                    title="对象引用越权（IDOR）", fid=None, metrics=None):
        fid = fid or ("f" + str(abs(hash((eng, status, title))) % 10 ** 23).zfill(23))
        ws.store.put_finding({
            "id": fid, "engagement_id": eng, "template_id": "idor-object-ref",
            "title": title, "status": status, "confidence": confidence,
            "evidence_ids": list(evidence_ids),
            "verdict": {"rationale": "B 身份读到了 A 的对象",
                        "metrics": metrics or {"similarity": 0.97}},
            "created_at": NOW,
        })
        return fid

    def test_html_is_written_and_self_contained(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e])
        out = os.path.join(self.tmp, "out")
        export_report(ws, out, ReportOptions(html=True), generated_at=NOW)

        path = os.path.join(out, "report.html")
        self.assertTrue(os.path.isfile(path))
        with open(path, encoding="utf-8") as fh:
            page = fh.read()
        self.assertTrue(page.lower().startswith("<!doctype html>"))
        self.assertIn("对象引用越权", page)
        # 单文件：不许有任何外部资源，双击/发邮件都能看
        for bad in ("<link", "<script src", "http://", "https://", "@import"):
            self.assertNotIn(bad, page, bad)

    def test_html_escapes_finding_text(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e], title='<img src=x onerror=alert(1)>')
        out = os.path.join(self.tmp, "out")
        export_report(ws, out, ReportOptions(html=True), generated_at=NOW)
        with open(os.path.join(out, "report.html"), encoding="utf-8") as fh:
            page = fh.read()
        self.assertIn("&lt;img", page)
        self.assertNotIn("<img", page)

    def test_merge_two_engagements_marks_each_round(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e], eng=ENG, title="第一轮：IDOR")
        self.add_finding(ws, [e], eng=ENG2, title="第二轮：IDOR", confidence=0.72,
                         status="hypothesis")
        out = os.path.join(self.tmp, "out")
        m = export_report(ws, out, ReportOptions(engagements=(ENG, ENG2)), generated_at=NOW)

        self.assertEqual(m["engagements"], [ENG, ENG2])
        with open(os.path.join(out, "findings.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["engagements"], [ENG, ENG2])
        self.assertEqual(len(data["findings"]), 2)
        self.assertEqual(sorted(f["engagement"] for f in data["findings"]), sorted([ENG, ENG2]))
        with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("等 2 轮", md)
        self.assertIn(ENG2, md)

    def test_default_stays_on_current_engagement(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e], eng=ENG)
        self.add_finding(ws, [e], eng=ENG2, title="别的轮次")
        out = os.path.join(self.tmp, "out")
        m = export_report(ws, out, generated_at=NOW)
        self.assertEqual(m["engagements"], [ENG])
        self.assertEqual(m["counts"]["findings"], 1)

    def test_list_engagements_only_lists_real_ones(self):
        ws = self.ws_with()
        rows = ws.store.list_engagements()
        self.assertEqual([r["id"] for r in rows], [ENG])

    def test_html_and_md_agree_on_counts(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e])
        self.add_finding(ws, [e], eng=ENG2, title="另一条", status="refuted", confidence=0.1)
        out = os.path.join(self.tmp, "out")
        m = export_report(ws, out, ReportOptions(html=True, engagements=(ENG, ENG2)),
                          generated_at=NOW)
        with open(os.path.join(out, "report.html"), encoding="utf-8") as fh:
            page = fh.read()
        self.assertIn(">%d<" % m["counts"]["findings"], page.replace(" ", ""))


if __name__ == "__main__":
    unittest.main()
