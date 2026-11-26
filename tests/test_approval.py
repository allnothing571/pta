"""验收④：L2 无审批 = pending_approval；批准后放行；once 用后即焚。"""
import unittest

from pta.approvals import approval_fingerprint
from pta.probe import ProbeRequest
from pta.transport import MockRoute
from support import WorkspaceCase


ROUTES = [
    MockRoute("GET", "app.test", "/api/fetch", 200, (("Content-Type", "text/plain"),), b"ok"),
]


class ApprovalTest(WorkspaceCase):
    def ws(self):
        ws = self.make_ws(ROUTES)
        ws.probe.oob_host = "oob.test"
        return ws

    def l2_request(self, action_id="a1"):
        return ProbeRequest(
            action_id=action_id,
            url="http://app.test/api/fetch?url=http://example.com",
            identity="A",
            label="ssrf",
            param_path="query:url",
            payload_class="oob_url",
        )

    def test_l2_without_approval_is_pending(self):
        ws = self.ws()
        res = ws.probe.run(self.l2_request())
        self.assertEqual(res.status, "pending_approval")
        self.assertIsNotNone(res.approval_fp)
        self.assertEqual(len(ws.store.list_evidence("ENG-T", "ssrf")), 0)
        pending = ws.store.logs("ENG-T", "pending_approval")
        self.assertEqual(len(pending), 1)

    def test_l1_auto_allowed(self):
        ws = self.ws()
        res = ws.probe.run(ProbeRequest(
            action_id="a2", url="http://app.test/api/fetch?url=1", identity="A",
            label="l1", param_path="query:url", payload_class="syntax_break",
        ))
        self.assertEqual(res.status, "ok", res.reason)

    def test_approve_class_then_allowed(self):
        ws = self.ws()
        first = ws.probe.run(self.l2_request())
        ws.gate.decide("ENG-T", "http_probe", "app.test", "query:url", "oob_url", "L2",
                       "approve", scope="class")
        second = ws.probe.run(self.l2_request("a2"))
        self.assertEqual(second.status, "ok", second.reason)
        self.assertEqual(first.approval_fp, second.approval_fp)

    def test_once_scope_is_consumed(self):
        ws = self.ws()
        ws.probe.run(self.l2_request())
        ws.gate.decide("ENG-T", "http_probe", "app.test", "query:url", "oob_url", "L2",
                       "approve", scope="once")
        self.assertEqual(ws.probe.run(self.l2_request("a2")).status, "ok")
        third = ws.probe.run(self.l2_request("a3"))
        self.assertEqual(third.status, "pending_approval")

    def test_reject_blocks(self):
        ws = self.ws()
        ws.probe.run(self.l2_request())
        ws.gate.decide("ENG-T", "http_probe", "app.test", "query:url", "oob_url", "L2",
                       "reject", note="不建议")
        res = ws.probe.run(self.l2_request("a2"))
        self.assertEqual(res.status, "pending_approval")
        self.assertIn("rejected", res.reason)

    def test_fingerprint_is_stable(self):
        a = approval_fingerprint("http_probe", "app.test", "query:url", "oob_url", "L2")
        b = approval_fingerprint("http_probe", "app.test", "query:url", "oob_url", "L2")
        c = approval_fingerprint("http_probe", "app.test", "query:id", "oob_url", "L2")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 24)


if __name__ == "__main__":
    unittest.main()
