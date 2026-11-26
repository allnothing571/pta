"""验收①③②：范围拦截、采样合并、证据复现与篡改检测。"""
import json
import os
import unittest

from pta.errors import EvidenceCorrupted
from pta.probe import ProbeRequest
from support import WorkspaceCase, idor_routes


class EvidenceTest(WorkspaceCase):
    def test_sample_merges_into_one_evidence(self):
        """验收③：同一请求采样 5 次 = 1 条证据，timings 长度 5。"""
        ws = self.make_ws(idor_routes())
        res = ws.probe.run(ProbeRequest(
            action_id="a1", url="http://app.test/api/users/1", identity="A",
            label="sampled", sample=5,
        ))
        self.assertEqual(res.status, "ok", res.reason)
        rows = ws.store.list_evidence("ENG-T", "sampled")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sample_count"], 5)
        self.assertEqual(len(ws.store.timings(res.evidence_id)), 5)

    def test_evidence_id_is_deterministic(self):
        ws = self.make_ws(idor_routes())
        a = ws.probe.run(ProbeRequest(action_id="a1", url="http://app.test/api/users/1",
                                      identity="A", label="x"))
        b = ws.probe.run(ProbeRequest(action_id="a2", url="http://app.test/api/users/1",
                                      identity="A", label="x"))
        self.assertEqual(a.evidence_id, b.evidence_id)
        self.assertEqual(len(ws.store.list_evidence("ENG-T", "x")), 1)

    def test_identity_changes_evidence_id(self):
        ws = self.make_ws(idor_routes())
        a = ws.probe.run(ProbeRequest(action_id="a1", url="http://app.test/api/users/1",
                                      identity="A", label="x"))
        b = ws.probe.run(ProbeRequest(action_id="a2", url="http://app.test/api/users/1",
                                      identity="B", label="x"))
        self.assertNotEqual(a.evidence_id, b.evidence_id)

    def test_scope_denied_is_logged(self):
        """验收①：范围外目标被拒，且 action_log 有 denied 记录。"""
        ws = self.make_ws(idor_routes())
        res = ws.probe.run(ProbeRequest(action_id="a9", url="http://evil.example.com/x",
                                        identity="A", label="x"))
        self.assertEqual(res.status, "denied")
        denied = ws.store.logs("ENG-T", "denied")
        self.assertTrue(denied)
        self.assertIn("evil.example.com", denied[0]["reason"])

    def test_dns_pin_blocks_private_resolution(self):
        from pta.scope import DnsPin
        ws = self.make_ws(idor_routes(), allow_private=False)
        ws.probe.dns = DnsPin(resolver=lambda host: ["127.0.0.1"])
        res = ws.probe.run(ProbeRequest(action_id="a10", url="http://app.test/api/users/1",
                                        identity="A", label="x"))
        self.assertEqual(res.status, "denied")
        self.assertIn("dns_pin", res.reason)

    def test_replay_matches_and_detects_tamper(self):
        """验收②：证据可 replay；CAS 被改则报 EvidenceCorrupted。"""
        ws = self.make_ws(idor_routes())
        res = ws.probe.run(ProbeRequest(action_id="a1", url="http://app.test/api/users/1",
                                        identity="A", label="r"))
        out = ws.replayer.replay(res.evidence_id)
        self.assertTrue(out["match"], out)

        row = ws.store.get_evidence_row(res.evidence_id)
        path = ws.cas.path_for(row["body_sha256"])
        with open(path, "r+b") as fh:
            data = bytearray(fh.read())
            data[-1] ^= 0xFF
            fh.seek(0)
            fh.write(data)
        with self.assertRaises(EvidenceCorrupted):
            ws.replayer.replay(res.evidence_id)

    def test_manifest_chain_verifies(self):
        ws = self.make_ws(idor_routes())
        ws.probe.run(ProbeRequest(action_id="a1", url="http://app.test/api/users/1",
                                  identity="A", label="m"))
        self.assertTrue(ws.cas.manifest.verify())

    def test_extract_has_no_raw_token(self):
        ws = self.make_ws(idor_routes())
        res = ws.probe.run(ProbeRequest(action_id="a1", url="http://app.test/api/users/1",
                                        identity="A", label="e"))
        dumped = json.dumps(res.to_json(), ensure_ascii=False)
        self.assertNotIn("TOKEN-A", dumped)


if __name__ == "__main__":
    unittest.main()
