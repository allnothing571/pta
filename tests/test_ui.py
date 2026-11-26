"""操作台（静态页 + 富化 API）的回归测试。

覆盖的是"界面能不能拿到它需要的东西"，不是像素：
- 页面与两个静态文件可托管，且只按白名单服务（拒绝目录穿越）；
- /api/state 里模板、tally、证据摘要、pending 的 param_path 都在；
- 证据详情带 request / headers / timings / body_preview；
- raw 必须 confirm=1，diff 给出相似度与头差异；
- /api/run 是异步的：202 + SSE 的 run_started / run_finished。
"""
import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from pta import vhx
from pta.api import make_server
from pta.probe import ProbeRequest
from pta.transport import MockRoute
from support import WorkspaceCase


BODY_A = b"line1\nline2\nline3\nline4\nline5"
BODY_B = b"line1\nline2\nline3\nline4\nline5\nline6"

ROUTES = [
    MockRoute("GET", "app.test", "/api/fetch", 200,
              (("Content-Type", "text/plain"), ("X-Trace", "t1")), BODY_A),
    MockRoute("GET", "app.test", "/api/other", 200,
              (("Content-Type", "application/json"), ("X-Trace", "t2")), BODY_B),
]


class UiTest(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.ws = self.make_ws(ROUTES)
        self.ws.probe.oob_host = "oob.test"
        self.httpd, _ = make_server(self.ws, bus=self.ws.bus, port=0)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.shutdown)

    # ---------- HTTP 小工具 ----------
    def url(self, path):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def raw(self, path, method="GET", payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.url(path), data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers, r.read()

    def get(self, path):
        status, headers, body = self.raw(path)
        return json.loads(body.decode("utf-8"))

    def post(self, path, payload):
        status, _, body = self.raw(path, "POST", payload)
        return json.loads(body.decode("utf-8"))

    def assertStatus(self, path, code):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.raw(path)
        self.assertEqual(ctx.exception.code, code)

    def probe(self, label="t1", identity="A", path="/api/fetch"):
        return self.ws.probe.run(ProbeRequest(
            action_id="a-" + label, url="http://app.test%s?x=1" % path,
            identity=identity, label=label))

    # ---------- 静态托管 ----------
    def test_index_is_served(self):
        status, headers, body = self.raw("/")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        html = body.decode("utf-8")
        self.assertIn("假设队列", html)
        self.assertIn("/ui/app.js", html)
        self.assertIn('id="run-dialog"', html)

    def test_assets_served_from_both_roots(self):
        for path in ("/ui/app.js", "/app.js"):
            status, headers, body = self.raw(path)
            self.assertEqual(status, 200)
            self.assertIn("javascript", headers["Content-Type"])
            self.assertIn(b"renderFindings", body)
        status, headers, body = self.raw("/style.css")
        self.assertEqual(status, 200)
        self.assertIn(b"--accent", body)

    def test_static_is_whitelisted(self):
        self.assertStatus("/ui/../api.py", 404)
        self.assertStatus("/ui/secret.txt", 404)
        self.assertStatus("/api/unknown", 404)

    # ---------- /api/state ----------
    def test_state_shape(self):
        self.probe()
        s = self.get("/api/state")
        self.assertEqual(s["engagement"], "ENG-T")
        self.assertEqual(s["engagement_detail"]["signed_by"], "local-operator")
        self.assertEqual(len(s["templates"]), len(vhx.TEMPLATES))
        ids = {t["id"] for t in s["templates"]}
        self.assertIn("sqli-time-blind", ids)
        self.assertIn("mass-assignment-privilege", ids)
        self.assertIn("sqli-boolean-blind", ids)
        time_blind = [t for t in s["templates"] if t["id"] == "sqli-time-blind"][0]
        self.assertEqual(time_blind["side_effect_level"], "L2")
        self.assertTrue(time_blind["requires_approval"])
        self.assertIn("timing_sample", time_blind["sequence"])
        self.assertEqual(s["breaker"], "closed")
        self.assertEqual(s["tally"]["refuted"], 0)
        ev = s["evidence"][0]
        for key in ("evidence_id", "label", "identity", "method", "host",
                    "raw_path", "status", "samples", "port", "content_type"):
            self.assertIn(key, ev)
        self.assertEqual(ev["method"], "GET")

    def test_pending_carries_param_path(self):
        self.ws.probe.run(ProbeRequest(
            action_id="a1", url="http://app.test/api/fetch?url=x", identity="A",
            label="ssrf", param_path="query:url", payload_class="oob_url"))
        s = self.get("/api/state")
        self.assertEqual(len(s["pending_approvals"]), 1)
        pending = s["pending_approvals"][0]
        self.assertEqual(pending["level"], "L2")
        self.assertEqual(pending["param_path"], "query:url")
        self.assertEqual(pending["payload_class"], "oob_url")
        self.assertTrue(pending["fp"])
        self.assertIn("url=", pending["url"])

    def test_findings_expose_rationale_and_metrics(self):
        self.ws.store.put_finding({
            "id": "f1", "engagement_id": "ENG-T", "template_id": "idor-object-ref",
            "title": "直接读对象", "status": "confirmed", "confidence": 0.88,
            "evidence_ids": ["e1", "e2"],
            "verdict": {"rationale": "两次响应同体", "metrics": {"jaccard": 0.97}},
            "created_at": "2026-11-10T00:00:00Z",
        })
        f = self.get("/api/state")["findings"][0]
        self.assertEqual(f["rationale"], "两次响应同体")
        self.assertEqual(f["metrics"]["jaccard"], 0.97)
        self.assertEqual(f["evidence_ids"], ["e1", "e2"])

    # ---------- 证据 ----------
    def test_evidence_detail(self):
        r = self.probe()
        d = self.get("/api/evidence/%s" % r.evidence_id)
        self.assertEqual(d["status"], 200)
        self.assertIn("line1", d["body_preview"])
        self.assertEqual(len(d["timings"]), 1)
        self.assertGreater(d["timings"][0], 0.0)
        self.assertEqual(d["headers"][0][0], "Content-Type")
        self.assertEqual(d["request"]["method"], "GET")
        self.assertEqual(d["request"]["host"], "app.test")
        self.assertEqual(d["request"]["raw_path"], "/api/fetch")
        self.assertEqual(d["request"]["query"], [["x", "1"]])

    def test_raw_requires_confirm(self):
        r = self.probe()
        self.assertStatus("/api/evidence/%s/raw" % r.evidence_id, 403)
        d = self.get("/api/evidence/%s/raw?confirm=1" % r.evidence_id)
        self.assertEqual(d["text"], BODY_A.decode())
        self.assertFalse(d["binary"])
        self.assertEqual(d["body_len"], len(BODY_A))

    def test_unknown_evidence_404(self):
        self.assertStatus("/api/evidence/deadbeef", 404)
        self.assertStatus("/api/evidence/deadbeef/raw?confirm=1", 404)

    def test_diff(self):
        a = self.probe("t1")
        b = self.probe("t2", path="/api/other")
        d = self.get("/api/evidence/%s/diff/%s" % (a.evidence_id, b.evidence_id))
        self.assertEqual(d["a"]["status"], 200)
        self.assertFalse(d["body_same"])
        self.assertGreater(d["similarity"], 0.8)
        names = [c["name"] for c in d["header_changes"]]
        self.assertIn("content-type", names)
        # 同一条证据跟自己比：完全一致
        same = self.get("/api/evidence/%s/diff/%s" % (a.evidence_id, a.evidence_id))
        self.assertTrue(same["body_same"])
        self.assertEqual(same["similarity"], 1.0)
        self.assertEqual(same["header_changes"], [])

    # ---------- 异步执行 ----------
    def test_run_is_async_and_reports_via_sse(self):
        q = self.ws.bus.subscribe()
        out = self.post("/api/run", {"template": "info-disclosure-artifact",
                                    "url": "http://app.test/.env"})
        self.assertTrue(out["ok"])
        self.assertEqual(out["state"], "running")
        self.assertTrue(out["run_id"])

        seen = []
        deadline = time.time() + 10
        while time.time() < deadline:
            ev = q.get(timeout=5)
            seen.append(ev["type"])
            if ev["type"] in ("run_finished", "run_failed"):
                break
        self.assertIn("run_started", seen)
        self.assertIn("run_finished", seen)
        self.assertEqual(seen[-1], "run_finished")

        findings = self.get("/api/state")["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["template_id"], "info-disclosure-artifact")

    def test_run_rejects_unknown_template(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.raw("/api/run", "POST", {"template": "nope", "url": "http://app.test/"})
        self.assertEqual(ctx.exception.code, 400)

    def test_override_finding(self):
        self.ws.store.put_finding({
            "id": "f9", "engagement_id": "ENG-T", "template_id": "x", "title": "t",
            "status": "confirmed", "confidence": 0.9, "evidence_ids": [],
            "verdict": {}, "created_at": "2026-11-10T00:00:00Z"})
        out = self.post("/api/findings/f9/override", {"status": "refuted"})
        self.assertTrue(out["ok"])
        row = self.ws.store.list_findings("ENG-T")[0]
        self.assertEqual(row["status"], "refuted")
        self.assertEqual(row["overridden_by"], "operator")

    def test_logs_endpoint(self):
        self.probe()
        rows = self.get("/api/logs?limit=10")
        self.assertTrue(rows)
        self.assertIn("decision", rows[0])


class StoreLockTest(WorkspaceCase):
    """同一 sqlite 连接跨线程写：行数必须与写入次数一致，不能出现半截事务。"""

    def test_concurrent_writes_are_atomic(self):
        ws = self.make_ws(ROUTES)
        errors = []

        def work(tag):
            try:
                for i in range(20):
                    ws.store.log_action("ENG-T", "probe", "ok", reason="r-%s-%d" % (tag, i),
                                        host="app.test", url="/x", level="L0")
            except Exception as exc:                      # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        rows = ws.store.logs("ENG-T")
        self.assertEqual(len(rows), 80)


if __name__ == "__main__":
    unittest.main()
