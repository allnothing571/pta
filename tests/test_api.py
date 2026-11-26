"""审批 API + SSE 的回归测试（纯标准库 http.server）。"""
import json
import queue
import threading
import unittest
import urllib.request

from pta.api import make_server
from pta.probe import ProbeRequest
from pta.transport import MockRoute
from support import WorkspaceCase


ROUTES = [MockRoute("GET", "app.test", "/api/fetch", 200, (("Content-Type", "text/plain"),), b"ok")]


class ApiTest(WorkspaceCase):
    def start(self):
        ws = self.make_ws(ROUTES)
        ws.probe.oob_host = "oob.test"
        httpd, bus = make_server(ws, bus=ws.bus, port=0)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        self.addCleanup(httpd.shutdown)
        return ws, httpd.server_port, bus

    def get(self, port, path):
        with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))

    def post(self, port, path, payload):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (port, path),
            data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))

    def l2(self, ws, action="a1"):
        return ws.probe.run(ProbeRequest(
            action_id=action, url="http://app.test/api/fetch?url=x", identity="A",
            label="ssrf", param_path="query:url", payload_class="oob_url"))

    def test_state_and_pending(self):
        ws, port, _ = self.start()
        res = self.l2(ws)
        state = self.get(port, "/api/state")
        self.assertEqual(state["engagement"], "ENG-T")
        fps = [p["fp"] for p in state["pending_approvals"]]
        self.assertIn(res.approval_fp, fps)

    def test_decide_via_http_then_allowed(self):
        ws, port, bus = self.start()
        q = bus.subscribe()
        res = self.l2(ws)
        ev = q.get(timeout=3)
        self.assertEqual(ev["type"], "approval_required")
        self.assertEqual(ev["fp"], res.approval_fp)

        out = self.post(port, "/api/approvals/%s/decide" % res.approval_fp,
                        {"decision": "approve", "scope": "class"})
        self.assertTrue(out["ok"])
        ev2 = q.get(timeout=3)
        self.assertEqual(ev2["type"], "approval_decided")
        self.assertEqual(self.l2(ws, "a2").status, "ok")

    def test_unknown_fp_404(self):
        _, port, _ = self.start()
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post(port, "/api/approvals/deadbeef/decide", {"decision": "approve"})
        self.assertEqual(ctx.exception.code, 404)

    def test_evidence_endpoint(self):
        ws, port, _ = self.start()
        r = ws.probe.run(ProbeRequest(action_id="a1", url="http://app.test/api/fetch?url=1",
                                      identity="A", label="x"))
        body = self.get(port, "/api/evidence/%s" % r.evidence_id)
        self.assertEqual(body["evidence_id"], r.evidence_id)
        self.assertEqual(body["status"], 200)

    def test_critic_endpoint(self):
        ws, port, _ = self.start()
        ws.store.put_finding({"id": "f1", "engagement_id": ws.scope.engagement_id,
                              "template_id": "idor-object-ref", "title": "t",
                              "status": "confirmed", "confidence": 0.5,
                              "evidence_ids": ["deadbeef"],
                              "verdict": {"metrics": {}, "rationale": "x"},
                              "created_at": "2026-11-09T00:00:00Z"})
        out = self.post(port, "/api/critic", {})
        self.assertEqual(out["reviewed"], 1)
        self.assertEqual(out["counts"]["vetoed"], 1)
        codes = [b["code"] for b in out["critiques"][0]["blocks"]]
        self.assertIn("evidence_missing", codes)
        self.assertIn("confidence_status_mismatch", codes)

    def test_critic_dry_run_keeps_status(self):
        ws, port, _ = self.start()
        ws.store.put_finding({"id": "f2", "engagement_id": ws.scope.engagement_id,
                              "template_id": "idor-object-ref", "title": "t",
                              "status": "confirmed", "confidence": 0.5,
                              "evidence_ids": ["deadbeef"],
                              "verdict": {"metrics": {}, "rationale": "x"},
                              "created_at": "2026-11-09T00:00:00Z"})
        self.post(port, "/api/critic", {"apply": False})
        self.assertEqual(ws.store.list_findings(ws.scope.engagement_id)[0]["status"],
                         "confirmed")

    def test_run_without_scheme_is_rejected_before_any_request(self):
        """没有 scheme 的 URL 要当场 400：否则它会变成一条「范围拒绝」的 refuted 结论。"""
        ws, port, _ = self.start()
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post(port, "/api/run",
                      {"template": "idor-object-ref", "url": "app.test:443/api/fetch"})
        self.assertEqual(ctx.exception.code, 400)
        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(body["error"], "bad_url")
        self.assertEqual(ws.store.list_findings(ws.scope.engagement_id), [])
        self.assertEqual(ws.store.count_sent(ws.scope.engagement_id), 0)


if __name__ == "__main__":
    unittest.main()
