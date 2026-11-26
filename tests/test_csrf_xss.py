"""F 项第一批：CSRF 令牌未被强制、存储型 XSS 标记被渲染。

两层测试：
  1) oracle 单测 —— 手工造 Observation，把每条降级分支都钉住；
  2) 端到端 —— 自己写 Transport（MockRoute 不能按 header 分态），
     跑完整 Executor，确认「带令牌 200 / 摘令牌 200」真的能出 confirmed。
"""
from __future__ import annotations

import json
import unittest
from typing import Dict, List, Tuple

from pta import payloads, vhx
from pta.executor import Executor, Target
from pta.models import RawResponse
from pta.oracles import CsrfTokenNotEnforced, Observation, StoredMarkerReflected
from pta.transport import Transport
from pta.workspace import open_workspace
from support import WorkspaceCase, fake_dns

ENG = "ENG-T"  # 必须与 WorkspaceCase 里 Scope 的 engagement_id 一致：证据按它落库、按它查
NONCE = "pta3f9c1a7b"
MARKER_TAG = '<img src=x data-pta="%s" onerror="void(0)">' % NONCE


def obs(role: str, status: int, body: bytes = b"{}", ctype: str = "application/json",
        identity: str = "A", method: str = "POST", url: str = "http://app.test/api/x",
        eid: str = "") -> Observation:
    return Observation(role=role, evidence_id=eid or "%s-%d" % (role, status),
                       identity=identity, method=method, url=url, status=status,
                       content_type=ctype, body_sha256="0" * 64, body_len=len(body),
                       body=body)


def _resp(status: int, body: bytes = b"{}",
          ctype: str = "application/json") -> RawResponse:
    return RawResponse(status=status, reason="x", http_version="HTTP/1.1",
                       headers=(("Content-Type", ctype),), body=body,
                       t_send=0.0, t_first_byte=0.0, t_end=0.0)


# ---------------------------------------------------------------- oracle 单测
class CsrfOracleTest(unittest.TestCase):
    def judge(self, observations):
        return CsrfTokenNotEnforced().run(observations, CsrfTokenNotEnforced.Args())

    def test_token_stripped_and_still_accepted(self):
        v = self.judge([obs("baseline", 200), obs("probe", 200)])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.75, places=2)
        self.assertIn("没做匿名对照", v.rationale)

    def test_anonymous_control_rejected_lifts_to_090(self):
        v = self.judge([obs("baseline", 200), obs("probe", 200),
                        obs("control", 403, identity="none")])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.90, places=2)
        self.assertEqual(v.metrics["anon_status"], 403)

    def test_anonymous_control_accepted_is_not_csrf(self):
        v = self.judge([obs("baseline", 200), obs("probe", 200),
                        obs("control", 200, identity="none")])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.20, places=2)
        self.assertIn("没做授权", v.rationale)

    def test_stripped_token_rejected(self):
        v = self.judge([obs("baseline", 200), obs("probe", 403)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.0, places=2)
        self.assertIn("防护在起作用", v.rationale)

    def test_baseline_failed_means_test_invalid(self):
        v = self.judge([obs("baseline", 403), obs("probe", 200)])
        self.assertFalse(v.passed)
        self.assertIn("不成立", v.rationale)

    def test_reject_word_in_body_is_not_a_pass(self):
        body = b'{"error": "csrf token invalid"}'
        v = self.judge([obs("baseline", 200), obs("probe", 200, body=body)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.10, places=2)


class StoredOracleTest(unittest.TestCase):
    def judge(self, observations):
        return StoredMarkerReflected().run(observations, StoredMarkerReflected.Args())

    def test_raw_html_is_confirmed(self):
        html = b"<html><body><div class=c>%s</div></body></html>" % MARKER_TAG.encode()
        v = self.judge([obs("probe", 201, b'{"id":1}'),
                        obs("verify", 200, html, ctype="text/html; charset=utf-8")])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.92, places=2)
        self.assertTrue(v.metrics["in_tag"])

    def test_escaped_marker_is_not_xss(self):
        html = (b'<html><body><div class=c>&lt;img src=x data-pta="%s" '
                b'onerror=&quot;void(0)&quot;&gt;</div></body></html>' % NONCE.encode())
        v = self.judge([obs("probe", 201), obs("verify", 200, html, ctype="text/html")])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.15, places=2)
        self.assertTrue(v.metrics["escaped"])

    def test_json_output_is_only_stored(self):
        body = json.dumps({"content": MARKER_TAG}).encode()
        v = self.judge([obs("probe", 201), obs("verify", 200, body)])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.35, places=2)

    def test_no_readback_is_zero(self):
        v = self.judge([obs("probe", 201)])
        self.assertFalse(v.passed)
        self.assertIn("写进去不等于别人能看到", v.rationale)

    def test_probe_echo_only(self):
        v = self.judge([obs("probe", 201, MARKER_TAG.encode()),
                        obs("verify", 200, b"<html><body>nothing</body></html>",
                            ctype="text/html")])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.10, places=2)

    def test_marker_outside_our_tag_is_weaker(self):
        html = b"<html><body><p>%s</p></body></html>" % NONCE.encode()
        v = self.judge([obs("probe", 201), obs("verify", 200, html, ctype="text/html")])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.30, places=2)


# ------------------------------------------------------------------- 端到端站
class CsrfServer(Transport):
    """按 header 分态：有无 x-csrf-token 是两件事，MockRoute 表达不了。"""

    name = "csrf"

    def __init__(self, enforce: bool = False):
        self.enforce = enforce
        self.sent: List[Dict[str, str]] = []

    def send(self, req, timeout_s: float = 10.0) -> RawResponse:
        h = {k.lower(): v for k, v in req.headers}
        self.sent.append({"method": req.method, "path": req.raw_path,
                          "token": h.get("x-csrf-token", ""),
                          "auth": h.get("authorization", "")})
        if not h.get("authorization"):
            return _resp(401, b'{"error": "unauthorized"}')
        if self.enforce and h.get("x-csrf-token", "") != "s3cr3t":
            return _resp(403, b'{"error": "csrf token invalid"}')
        return _resp(200, b'{"ok": true, "updated": 1}')


class CommentServer(Transport):
    """写进去、读回来：GET 把存下的内容原样插进 HTML（这就是存储型 XSS）。"""

    name = "comments"

    def __init__(self, escape: bool = False):
        self.escape = escape
        self.items: List[str] = []
        self.sent: List[Dict[str, str]] = []

    def send(self, req, timeout_s: float = 10.0) -> RawResponse:
        self.sent.append({"method": req.method, "path": req.raw_path})
        if req.method.upper() == "POST":
            try:
                data = json.loads(req.body.decode("utf-8") or "{}")
            except ValueError:
                data = {}
            self.items.append(str(data.get("content") or ""))
            return _resp(201, b'{"id": %d}' % len(self.items))
        rows = []
        for text in self.items:
            if self.escape:
                text = (text.replace("&", "&amp;").replace("<", "&lt;")
                        .replace(">", "&gt;").replace('"', "&quot;"))
            rows.append("<div class=c>%s</div>" % text)
        html = "<html><body>%s</body></html>" % "".join(rows)
        return _resp(200, html.encode("utf-8"), "text/html; charset=utf-8")


class EndToEndCase(WorkspaceCase):
    def setUp(self) -> None:
        super().setUp()
        # 载荷类必须在跑之前就注册好：模板 lint 通过但载荷缺失只会在发送时才炸
        self.assertIn("stored_xss_marker", payloads.describe())

    def _ws(self, transport):
        ws = self.make_ws([], transport=transport)
        ws.vault.put("cred/A/x-csrf-token", "s3cr3t")
        return ws

    @staticmethod
    def _approve(ws, param_path, payload_class):
        ws.gate.decide(ENG, "http_probe", "app.test", param_path, payload_class,
                       "L2", "approve", scope="class")

    def test_csrf_without_enforcement_is_confirmed(self):
        srv = CsrfServer(enforce=False)
        ws = self._ws(srv)
        self._approve(ws, None, None)
        f = Executor(ws.probe, ws.store, ENG).run(
            vhx.load([t for t in vhx.TEMPLATES if t["id"] == "csrf-token-not-enforced"][0]),
            Target(url="http://app.test/api/update", method="POST",
                   identity_baseline="A", identity_probe="A",
                   control_url="http://app.test/api/update",
                   body_json={"nick": "x"}))
        self.assertEqual(f.status, "confirmed", f.verdict.get("rationale"))
        self.assertGreaterEqual(f.confidence, 0.90)
        # 顺序是 baseline → 匿名对照 → 摘令牌的 probe
        self.assertEqual(srv.sent[0]["token"], "s3cr3t")
        self.assertEqual(srv.sent[0]["auth"], "Bearer TOKEN-A")
        self.assertEqual(srv.sent[1]["auth"], "")
        self.assertEqual(srv.sent[2]["token"], "")
        self.assertEqual(srv.sent[2]["auth"], "Bearer TOKEN-A")

    def test_csrf_without_anonymous_control_stays_hypothesis(self):
        srv = CsrfServer(enforce=False)
        ws = self._ws(srv)
        self._approve(ws, None, None)
        f = Executor(ws.probe, ws.store, ENG).run(
            vhx.load([t for t in vhx.TEMPLATES if t["id"] == "csrf-token-not-enforced"][0]),
            Target(url="http://app.test/api/update", method="POST",
                   identity_baseline="A", identity_probe="A",
                   body_json={"nick": "x"}))
        self.assertEqual(f.status, "hypothesis")
        self.assertAlmostEqual(f.confidence, 0.75, places=2)
        self.assertIn("匿名对照", f.verdict.get("rationale") or "")

    def test_csrf_with_enforcement_is_refuted(self):
        srv = CsrfServer(enforce=True)
        ws = self._ws(srv)
        self._approve(ws, None, None)
        f = Executor(ws.probe, ws.store, ENG).run(
            vhx.load([t for t in vhx.TEMPLATES if t["id"] == "csrf-token-not-enforced"][0]),
            Target(url="http://app.test/api/update", method="POST",
                   identity_baseline="A", identity_probe="A",
                   body_json={"nick": "x"}))
        self.assertEqual(f.status, "refuted")
        self.assertIn("防护在起作用", f.verdict.get("rationale") or "")

    def test_stored_xss_confirmed_when_readback_renders(self):
        srv = CommentServer(escape=False)
        ws = self._ws(srv)
        self._approve(ws, "body:content", "stored_xss_marker")
        f = Executor(ws.probe, ws.store, ENG).run(
            vhx.load([t for t in vhx.TEMPLATES if t["id"] == "xss-stored-marker"][0]),
            Target(url="http://app.test/api/comments", method="POST",
                   param_path="body:content",
                   identity_baseline="A", identity_probe="A",
                   body_json={"content": "hello", "author": "alice"}))
        self.assertEqual(f.status, "confirmed", f.verdict.get("rationale"))
        self.assertGreaterEqual(f.confidence, 0.92)
        self.assertEqual(srv.sent[-1]["method"], "GET")

    def test_stored_xss_refuted_when_escaped(self):
        srv = CommentServer(escape=True)
        ws = self._ws(srv)
        self._approve(ws, "body:content", "stored_xss_marker")
        f = Executor(ws.probe, ws.store, ENG).run(
            vhx.load([t for t in vhx.TEMPLATES if t["id"] == "xss-stored-marker"][0]),
            Target(url="http://app.test/api/comments", method="POST",
                   param_path="body:content",
                   identity_baseline="A", identity_probe="A",
                   body_json={"content": "hello", "author": "alice"}))
        self.assertEqual(f.status, "refuted")
        self.assertIn("转义", f.verdict.get("rationale") or "")


if __name__ == "__main__":
    unittest.main()
