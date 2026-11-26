"""浏览器链路测试：协议级假 CDP 服务器 + 真 WebSocket + 真 SQLite/CAS。

真 Chromium 在 DSH Windows 沙箱里起不来（命名管道被拒），所以这里用 fake_cdp 复刻
浏览器在 CDP 上的行为。被测的是我们自己的代码：websocket 帧、JSON-RPC 事件分发、
Fetch 拦截器的范围校验、DOM 快照证据、以及 xss 判定链。
"""
from __future__ import annotations

import copy
import unittest

from pta import cdp, vhx
from pta.browser import BrowserTool, NavRequest, open_page
from pta.executor import Executor, Target
from pta.oracles import DomMarkerPresent, Observation, build_oracle
from pta.errors import VhxInvalid

from fake_cdp import FakeCdpServer, FakePage
from support import WorkspaceCase, fake_dns


class BrowserCase(WorkspaceCase):
    mode = "vuln"
    foreign_url = None

    def setUp(self) -> None:
        super().setUp()
        self.ws = self.make_ws([])
        self.page = FakePage(mode=self.mode, foreign_url=self.foreign_url)
        self.server = FakeCdpServer(self.page).start()
        self.addCleanup(self.server.close)
        self.wsock = cdp.WebSocket("127.0.0.1", self.server.port, self.server.path, timeout=10)
        self.addCleanup(self.wsock.close)
        self.session = cdp.CdpSession(self.wsock)
        self.tool = BrowserTool(
            scope=self.ws.scope, store=self.ws.store, cas=self.ws.cas, budget=self.ws.budget,
            page_session=self.session, page_id="S1", target_id="T1",
            product="FakeCdp/1.0", dns=fake_dns(), bus=self.ws.bus,
        )

    def nav(self, url="http://app.test/search?q=hello", **kw):
        req = NavRequest(url=url, label="run/xss/test", settle_s=0.3, **kw)
        return self.tool.navigate(req)


class WebsocketFramingTest(BrowserCase):
    mode = "safe"

    def test_handshake_and_rpc(self):
        """握手 + 收发一帧（这条失败说明 websocket 帧编解码坏了）。"""
        res = self.session.call("Browser.getVersion", timeout=5)
        self.assertEqual(res, {})
        self.assertIn("Browser.getVersion", self.server.methods)

    def test_large_frame_roundtrip(self):
        """>125 字节的帧走 16 位长度字段。"""
        big = "x" * 4000
        self.session.call("Runtime.evaluate", {"expression": big}, timeout=5)
        self.assertIn("Runtime.evaluate", self.server.methods)


class DomSnapshotTest(BrowserCase):
    mode = "vuln"

    def test_navigate_returns_dom_snapshot_evidence(self):
        r = self.nav(param_path="query:q", payload_class="xss_marker")
        self.assertEqual(r.status, "ok", r.reason)
        self.assertTrue(r.evidence_id)
        row = self.ws.store.get_evidence_row(r.evidence_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["content_type"], "text/html; dom-snapshot")
        headers = {k.lower(): v for k, v in
                   (__import__("json").loads(row["headers_json"]) or [])}
        self.assertEqual(headers["x-pta-capture"], "dom-snapshot")
        self.assertTrue(headers["x-pta-nonce"])
        # 载荷 note 里带的 nonce 必须与证据头一致
        self.assertEqual(headers["x-pta-window-name"], headers["x-pta-nonce"])
        self.assertIn('data-pta-xss="%s"' % headers["x-pta-nonce"], self.page.html)

    def test_executor_confirms_xss(self):
        ex = Executor(self.ws.probe, self.ws.store, self.ws.scope.engagement_id, browser=self.tool)
        tpl = vhx.load(copy.deepcopy([t for t in vhx.TEMPLATES if t["id"] == "xss-reflected"][0]))
        f = ex.run(tpl, Target(url="http://app.test/search?q=hello",
                               param_path="query:q", identity_probe="none"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.85)
        self.assertEqual(len(f.evidence_ids), 1)
        self.assertEqual(f.requests_used, 1)

    def test_executor_requires_browser(self):
        ex = Executor(self.ws.probe, self.ws.store, self.ws.scope.engagement_id, browser=None)
        tpl = vhx.load(copy.deepcopy([t for t in vhx.TEMPLATES if t["id"] == "xss-reflected"][0]))
        with self.assertRaises(VhxInvalid):
            ex.run(tpl, Target(url="http://app.test/search?q=hello", param_path="query:q"))


class ReflectOnlyTest(BrowserCase):
    mode = "reflect"

    def test_reflected_without_execution_is_refuted(self):
        r = self.nav(param_path="query:q", payload_class="xss_marker")
        self.assertEqual(r.status, "ok")
        ex = Executor(self.ws.probe, self.ws.store, self.ws.scope.engagement_id, browser=self.tool)
        tpl = vhx.load(copy.deepcopy([t for t in vhx.TEMPLATES if t["id"] == "xss-reflected"][0]))
        f = ex.run(tpl, Target(url="http://app.test/search?q=hello", param_path="query:q"))
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertIn("只被反射", f.verdict["rationale"])


class SafePageTest(BrowserCase):
    mode = "safe"

    def test_encoded_payload_not_confirmed(self):
        r = self.nav(param_path="query:q", payload_class="xss_marker")
        self.assertEqual(r.status, "ok")
        ex = Executor(self.ws.probe, self.ws.store, self.ws.scope.engagement_id, browser=self.tool)
        tpl = vhx.load(copy.deepcopy([t for t in vhx.TEMPLATES if t["id"] == "xss-reflected"][0]))
        f = ex.run(tpl, Target(url="http://app.test/search?q=hello", param_path="query:q"))
        self.assertEqual(f.status, "refuted")


class ScopeInterceptionTest(BrowserCase):
    mode = "redirect"
    foreign_url = "https://evil.test/steal.js"

    def test_out_of_scope_subrequest_is_failed_and_logged(self):
        r = self.nav()
        self.assertEqual(r.status, "ok", r.reason)
        self.assertIn("https://evil.test/steal.js", r.denied_urls)
        rows = self.ws.store.logs(self.ws.scope.engagement_id)
        denied = [row for row in rows if row["decision"] == "denied"]
        self.assertTrue(denied)
        self.assertIn("evil.test", denied[0]["reason"] + denied[0]["url"])


class OracleUnitTest(unittest.TestCase):
    def obs(self, capture="dom-snapshot", nonce="abc12345", window="abc12345",
            body='<html><body data-pta-xss="abc12345">x</body></html>', role="probe"):
        return Observation(role=role, evidence_id="e1", identity="none", method="GET",
                           url="http://app.test/s?q=1", status=200,
                           content_type="text/html; dom-snapshot", body_sha256="0" * 64,
                           body_len=len(body), body=body.encode(), headers={
                               "x-pta-capture": capture, "x-pta-nonce": nonce,
                               "x-pta-window-name": window})

    def test_confirms_with_both_signals(self):
        v = build_oracle("dom_marker_present").run([self.obs()], DomMarkerPresent.Args())
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.9)

    def test_window_name_only(self):
        v = build_oracle("dom_marker_present").run(
            [self.obs(body="<html><body>x</body></html>")], DomMarkerPresent.Args())
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.92, places=2)

    def test_body_attr_only(self):
        """只有 body 属性（脚本跑到一半）→ 0.88，仍过 0.85 门槛。"""
        v = build_oracle("dom_marker_present").run(
            [self.obs(window="")], DomMarkerPresent.Args())
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.88, places=2)

    def test_require_window_name_rejects_body_only(self):
        v = build_oracle("dom_marker_present",
                         {"require_window_name": True}).run([self.obs(window="")],
                                                            DomMarkerPresent.Args(require_window_name=True))
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.60)

    def test_text_mention_is_not_execution(self):
        body = '<html><body>x <span>data-pta-xss="abc12345"</span></body></html>'
        v = build_oracle("dom_marker_present").run(
            [self.obs(window="", body=body)], DomMarkerPresent.Args())
        self.assertFalse(v.passed)
        self.assertTrue(v.metrics["reflected_only"])

    def test_non_dom_evidence_refuted(self):
        v = build_oracle("dom_marker_present").run(
            [self.obs(capture="http-response")], DomMarkerPresent.Args())
        self.assertFalse(v.passed)
        self.assertIn("probe:dom_snapshot", v.missing_evidence)

    def test_no_probe_missing(self):
        v = build_oracle("dom_marker_present").run([], DomMarkerPresent.Args())
        self.assertFalse(v.passed)
        self.assertIn("probe", v.missing_evidence)


class TemplateMetaTest(unittest.TestCase):
    def test_template_is_lint_clean(self):
        raw = [t for t in vhx.TEMPLATES if t["id"] == "xss-reflected"][0]
        self.assertEqual(vhx.lint(raw), [])
        self.assertEqual(raw["side_effect_level"], "L1")
        self.assertEqual(raw["oracle"]["name"], "dom_marker_present")
        self.assertIn("browser_nav", raw["probe"]["sequence"])

    def test_payload_is_registered(self):
        from pta import payloads
        self.assertIn("xss_marker", payloads.REGISTRY)
        val = payloads.render("xss_marker", nonce_value="deadbeef")
        self.assertIn("deadbeef", val)
        self.assertIn("onerror", val)


if __name__ == "__main__":
    unittest.main()
