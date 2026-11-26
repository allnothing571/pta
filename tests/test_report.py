"""报告导出：三层（人读 / 机器读 / 整包指纹）都要能自证。

这里不测"报告好看不好看"，只测四件可证伪的事：
1. 证据 id 能重算出对得上；
2. 正文脱敏真的生效；
3. 正文被改过 → verify.json 里指名道姓；
4. 同一份工作区导两次，root_sha256 一致（否则包不可比对）。
"""
from __future__ import annotations

import json
import os
import unittest

from pta.models import Body, CanonicalRequest, Evidence, Header
from pta.probe import ProbeRequest, compute_evidence_id
from pta.report import ReportOptions, export_report

from support import OBJECT_BODY, WorkspaceCase

NOW = "2026-01-02T03:04:05Z"


class ReportTest(WorkspaceCase):
    def ws_with(self, body=OBJECT_BODY, status=200):
        from pta.transport import MockRoute
        routes = [MockRoute("GET", "app.test", "/api/users/1", status,
                            (("Content-Type", "application/json"),), body)]
        return self.make_ws(routes)

    def seed(self, ws, body=None, label="baseline-A", identity="A",
             url="http://app.test/api/users/1"):
        res = ws.probe.run(ProbeRequest(action_id="a1", url=url, identity=identity, label=label))
        self.assertEqual(res.status, "ok")
        return res.evidence_id

    def add_finding(self, ws, evidence_ids, status="confirmed", confidence=0.99,
                    title="对象引用越权（IDOR）", metrics=None, fid=None):
        fid = fid or ("f" + str(abs(hash((status, title))) % 10 ** 23).zfill(23))
        ws.store.put_finding({
            "id": fid, "engagement_id": "ENG-T", "template_id": "idor-object-ref",
            "title": title, "status": status, "confidence": confidence,
            "evidence_ids": list(evidence_ids),
            "verdict": {"rationale": "B 身份读到了 A 的对象", "metrics": metrics or {"similarity": 0.97}},
            "created_at": NOW,
        })
        return fid

    def test_three_layers_are_written(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e])
        out = os.path.join(self.tmp, "out")
        m = export_report(ws, out, generated_at=NOW)

        self.assertTrue(os.path.isfile(os.path.join(out, "report.md")))
        self.assertTrue(os.path.isfile(os.path.join(out, "findings.json")))
        self.assertTrue(os.path.isfile(os.path.join(out, "manifest.json")))
        self.assertTrue(os.path.isfile(os.path.join(out, "verify.json")))
        self.assertTrue(os.path.isfile(os.path.join(out, "evidence", e + ".json")))
        self.assertTrue(os.path.isfile(os.path.join(out, "evidence", e + ".request.json")))
        self.assertTrue(os.path.isfile(os.path.join(out, "evidence", e + ".response.txt")))
        self.assertEqual(m["counts"]["findings"], 1)
        self.assertEqual(m["counts"]["evidence"], 1)
        self.assertEqual(m["verify"]["evidence_ok"], 1)

    def test_evidence_id_recomputes(self):
        ws = self.ws_with()
        e = self.seed(ws)
        out = os.path.join(self.tmp, "out")
        export_report(ws, out, ReportOptions(include_all_evidence=True), generated_at=NOW)
        with open(os.path.join(out, "evidence", e + ".json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        req = meta["canonical_request"]
        # 读者侧独立重算：sha256(json(req,body,label)) 应等于文件名
        import hashlib
        blob = json.dumps({"req": req, "body": meta["body_sha256"], "label": meta["label"]},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(hashlib.sha256(blob).hexdigest(), e)

    def test_root_hash_is_stable_across_runs(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e])
        a = export_report(ws, os.path.join(self.tmp, "a"), generated_at=NOW)
        b = export_report(ws, os.path.join(self.tmp, "b"), generated_at=NOW)
        self.assertEqual(a["root_sha256"], b["root_sha256"])

    def test_secret_in_body_is_redacted(self):
        ws = self.ws_with(b'{"token":"sk-live-ABCDEFGH12345678","id":1}')
        e = self.seed(ws)
        self.add_finding(ws, [e])
        out = os.path.join(self.tmp, "out")
        export_report(ws, out, generated_at=NOW)
        with open(os.path.join(out, "evidence", e + ".response.txt"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("sk-live-ABCDEFGH12345678", text)

    def test_extra_secret_is_replaced(self):
        ws = self.ws_with(b'{"note":"internal-marker-42"}')
        e = self.seed(ws)
        self.add_finding(ws, [e])
        out = os.path.join(self.tmp, "out")
        export_report(ws, out, ReportOptions(extra_secrets=("internal-marker-42",)), generated_at=NOW)
        with open(os.path.join(out, "evidence", e + ".response.txt"), encoding="utf-8") as fh:
            self.assertNotIn("internal-marker-42", fh.read())

    def test_tampered_body_is_reported(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e])
        row = ws.store.get_evidence_row(e)
        path = ws.cas.path_for(row["body_sha256"])
        with open(path, "wb") as fh:            # 换掉密文，plaintext 哈希必然变
            fh.write(ws.cas.cipher.encrypt(b'{"id":1,"role":"admin"}'))
        out = os.path.join(self.tmp, "out")
        m = export_report(ws, out, generated_at=NOW)
        reasons = {x["reason"] for x in m["verify"]["mismatches"]}
        self.assertIn("body_hash_mismatch", reasons)
        with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("不一致项", text)

    def test_binary_body_goes_base64(self):
        ws = self.ws_with(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
        e = self.seed(ws)
        self.add_finding(ws, [e])
        out = os.path.join(self.tmp, "out")
        export_report(ws, out, ReportOptions(include_all_evidence=True), generated_at=NOW)
        with open(os.path.join(out, "evidence", e + ".json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertEqual(meta["response_encoding"], "base64")
        self.assertTrue(os.path.isfile(os.path.join(out, meta["files"]["response"])))

    def test_unbound_finding_is_flagged(self):
        ws = self.ws_with()
        fid = self.add_finding(ws, [])
        out = os.path.join(self.tmp, "out")
        m = export_report(ws, out, generated_at=NOW)
        self.assertEqual(m["verify"]["unbound_findings"], [fid])
        with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
            self.assertIn("未绑定证据的结论", fh.read())

    def test_status_filter_and_no_bodies(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e], status="confirmed")
        self.add_finding(ws, [e], status="refuted", confidence=0.2, title="另一条否定结论")
        out = os.path.join(self.tmp, "out")
        m = export_report(ws, out, ReportOptions(statuses=("refuted",), include_bodies=False),
                          generated_at=NOW)
        self.assertEqual(m["counts"]["findings"], 1)
        self.assertFalse(os.path.isfile(os.path.join(out, "evidence", e + ".response.txt")))

    def test_report_md_has_reproduction_steps(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e])
        out = os.path.join(self.tmp, "out")
        export_report(ws, out, generated_at=NOW)
        with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("## 复核方法", text)
        self.assertIn("root_sha256", text)
        self.assertIn(e, text)
        self.assertIn("对象引用越权（IDOR）", text)

    def test_manifest_covers_every_file(self):
        ws = self.ws_with()
        e = self.seed(ws)
        self.add_finding(ws, [e])
        out = os.path.join(self.tmp, "out")
        export_report(ws, out, generated_at=NOW)
        with open(os.path.join(out, "manifest.json"), encoding="utf-8") as fh:
            m = json.load(fh)
        listed = {f["path"] for f in m["files"]}
        actual = set()
        for base, _d, names in os.walk(out):
            for n in names:
                rel = os.path.relpath(os.path.join(base, n), out).replace(os.sep, "/")
                if rel != "manifest.json":
                    actual.add(rel)
        self.assertEqual(listed, actual)
        import hashlib
        root = hashlib.sha256("\n".join("%s:%s" % (f["path"], f["sha256"])
                                       for f in m["files"]).encode("utf-8")).hexdigest()
        self.assertEqual(root, m["root_sha256"])


if __name__ == "__main__":
    unittest.main()
