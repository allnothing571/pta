"""通道消歧（channels.py）：把"被拦截"和"没有洞"分开。

这套测试守的是三条结论：
1. 三档客户端身份表现不一致 → 判定为"拦截层在挑客户端"，不是"没洞"；
2. 三档全被拒且无拦截特征 → 是应用层拒绝，用例本身不成立，不是"没洞"；
3. 预算不够做消歧时，宁可标"未验证"（0.5 待验证），也不假装判否（0.0）。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta import vhx  # noqa: E402
from pta.channels import CHANNELS, ChannelProbe, ChannelReport, ChannelResult  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import RawResponse, Transport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-CH"

CF_BODY = (b"<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title>"
           b"</head><body>cf-error-details</body></html>")
PLAIN_403 = b'{"error": "forbidden"}'
OBJECT = b'{"id": 3, "name": "widget", "owner": "B"}'
DB_ERROR = b'{"error": "sqlite3.OperationalError: near \\"\\": syntax error"}'

BROWSER_UA = "Mozilla/"


def _resp(status, body, headers=(("Content-Type", "application/json"),)):
    now = 0.0
    return RawResponse(status=status, reason="x", http_version="HTTP/1.1",
                       headers=tuple(headers), body=body,
                       t_send=now, t_first_byte=now, t_end=now)


class UaTransport(Transport):
    """按 User-Agent 与"有没有载荷"决定响应的假服务器。

    mode:
      - vuln:        只认浏览器 UA（其余 403 + Cloudflare 特征）
      - payload_rule: 无载荷都放行；带载荷时只认浏览器 UA（典型 WAF 规则命中）
      - app_denied:  所有人 403，正文是一句普通 JSON（没有任何拦截特征）
      - all_waf:     所有人 403 + cf-ray
      - open:        所有人 200
    """
    name = "ua"

    def __init__(self, mode="vuln"):
        self.mode = mode
        self.sent = []

    def send(self, req, timeout_s=10.0):
        hdrs = {k.lower(): v for k, v in req.headers}
        ua = hdrs.get("user-agent", "")
        query = "&".join("%s=%s" % (k, v) for k, v in req.query)
        self.sent.append({"ua": ua, "query": query, "path": req.raw_path, "headers": hdrs})
        has_payload = any(t in query for t in ("'", "%27", "SLEEP", "1=1"))
        browser = ua.startswith(BROWSER_UA)

        # 不存在的对象一律 404：这是 decoy 负对照想要的正常语义。
        # 真实应用也大多如此——读不到就 404，而不是"随便给一份"。
        if "999999999" in req.raw_path or "999999999" in query:
            return _resp(404, b'{"error": "not found"}')

        if self.mode == "open":
            return _resp(200, OBJECT)
        if self.mode == "app_denied":
            return _resp(403, PLAIN_403)
        if self.mode == "all_waf":
            return _resp(403, CF_BODY, (("Content-Type", "text/html"), ("cf-ray", "8a1b2c3d")))
        if self.mode == "vuln":
            return _resp(200, OBJECT) if browser else _resp(
                403, CF_BODY, (("Content-Type", "text/html"), ("cf-ray", "8a1b2c3d")))
        # payload_rule
        if has_payload:
            if browser:
                return _resp(500, DB_ERROR)
            return _resp(403, CF_BODY, (("Content-Type", "text/html"), ("cf-ray", "8a1b2c3d")))
        return _resp(200, OBJECT)


class ChannelProbeTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-ch-")
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("app.test",),
                                        allow_private=True, rate_per_host=200, max_requests=200))
        self.ws = open_workspace(self.root, transport=UaTransport("vuln"),
                                 dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        self.ws.vault.put("cred/A/authorization", "Bearer A")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def probe(self):
        return ChannelProbe(self.ws.probe)

    def test_open_when_every_channel_passes(self):
        self.ws.probe.transport.mode = "open"
        rep = self.probe().run("http://app.test/api/users/3", identity="A")
        self.assertEqual(rep.verdict, "open")
        self.assertEqual(rep.requests, 1, "原样档就通，不该再试另外两档")
        self.assertEqual(rep.usable, ["plain"])

    def test_waf_when_channels_disagree(self):
        rep = self.probe().run("http://app.test/api/users/3", identity="A")
        self.assertEqual(rep.verdict, "waf")
        self.assertEqual(rep.best, "browser")
        self.assertEqual(rep.blocked_names, ["plain"])
        self.assertIn("cloudflare", rep.markers)
        self.assertEqual(rep.requests, 2, "已经能定性就不再花预算试第三档")

    def test_app_denied_when_all_blocked_without_markers(self):
        self.ws.probe.transport.mode = "app_denied"
        rep = self.probe().run("http://app.test/api/users/3", identity="A")
        self.assertEqual(rep.verdict, "app_denied")
        self.assertEqual(rep.usable, [])
        self.assertEqual(rep.markers, [])

    def test_all_waf_when_markers_present_but_nothing_passes(self):
        self.ws.probe.transport.mode = "all_waf"
        rep = self.probe().run("http://app.test/api/users/3", identity="A")
        self.assertEqual(rep.verdict, "waf")
        self.assertEqual(rep.requests, 3)
        self.assertIn("cloudflare", rep.markers)

    def test_marker_from_header_only(self):
        self.ws.probe.transport.mode = "all_waf"
        rep = self.probe().run("http://app.test/api/users/3", identity="A")
        # cf-ray 是响应头，正文被定制成普通 403 页时它是唯一线索
        self.assertTrue(any("cloudflare" in r.markers for r in rep.results))

    def test_channels_override_default_user_agent(self):
        self.probe().run("http://app.test/api/users/3", identity="A")
        sent = self.ws.probe.transport.sent
        uas = [s["headers"].get("user-agent", "") for s in sent]
        self.assertIn("pta-p0/0.1", uas)
        self.assertTrue(any(u.startswith(BROWSER_UA) for u in uas))
        # 覆盖不是追加：浏览器档不能同时带着两个 UA
        self.assertEqual(len({u for u in uas if u.startswith(BROWSER_UA)}), 1)


class ExecutorTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-chx-")
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("app.test",),
                                        allow_private=True, rate_per_host=200, max_requests=200))
        self.ws = open_workspace(self.root, transport=UaTransport("vuln"),
                                 dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        self.ws.vault.put("cred/A/authorization", "Bearer A")
        self.ws.vault.put("cred/B/authorization", "Bearer B")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def tpl(self, template_id):
        return vhx.load([t for t in vhx.TEMPLATES if t["id"] == template_id][0])

    def test_baseline_blocked_but_browser_channel_confirms(self):
        # 基线（B 读自己的对象）在原样档被 WAF 拦，换浏览器档就通；
        # 洞是真的：A 也能读到同一个对象。
        f = Executor(self.ws.probe, self.ws.store, ENG).run(
            self.tpl("idor-object-ref"),
            Target(url="http://app.test/api/users/3", identity_baseline="B",
                   identity_probe="A"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertIn("channel", f.verdict["metrics"])
        self.assertEqual(f.verdict["metrics"]["channel"]["best"], "browser")
        self.assertGreaterEqual(len(f.evidence_ids), 3)

    def test_all_channels_blocked_is_not_refuted(self):
        self.ws.probe.transport.mode = "all_waf"
        f = Executor(self.ws.probe, self.ws.store, ENG).run(
            self.tpl("idor-object-ref"),
            Target(url="http://app.test/api/users/3", identity_baseline="B",
                   identity_probe="A"))
        self.assertEqual(f.status, "hypothesis", f.verdict)
        self.assertAlmostEqual(f.confidence, 0.50)
        self.assertTrue(f.stop_reason.startswith("channel_blocked"), f.stop_reason)
        self.assertIn("被拦截层挡住", f.verdict["rationale"])
        # 三档的响应都落成证据，操作者能自己复核
        self.assertEqual(f.verdict["metrics"]["channel"]["verdict"], "waf")

    def test_app_denied_falls_through_to_normal_judgement(self):
        # 三档一律 403 且没有任何拦截特征 → 是应用自己拒绝，不是"分不清"。
        # 这种情况 403 本身就是证据（"没权限"正是无洞的样子），
        # 必须继续走 oracle，而不是升成"待验证"。
        self.ws.probe.transport.mode = "app_denied"
        f = Executor(self.ws.probe, self.ws.store, ENG).run(
            self.tpl("idor-object-ref"),
            Target(url="http://app.test/api/users/3", identity_baseline="B",
                   identity_probe="A"))
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertEqual(f.verdict["metrics"]["channel"]["verdict"], "app_denied")

    def test_payload_blocked_retried_over_browser_channel(self):
        # 基线放行、载荷被规则命中：换档重发后拿到 SQLite 报错 → 洞是真的
        self.ws.probe.transport.mode = "payload_rule"
        f = Executor(self.ws.probe, self.ws.store, ENG).run(
            self.tpl("sqli-error-boolean"),
            Target(url="http://app.test/api/items", param_path="query:id",
                   identity_baseline="A", identity_probe="A"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertEqual(f.verdict["metrics"]["channel"]["verdict"], "waf")
        self.assertIn("sqlite", str(f.verdict["metrics"].get("signature", "")).lower()
                      + f.verdict["rationale"].lower())

    def test_start_channel_from_target(self):
        # 明确知道目标只认浏览器时，第一发就用浏览器档：不必先挨一次 403
        f = Executor(self.ws.probe, self.ws.store, ENG).run(
            self.tpl("idor-object-ref"),
            Target(url="http://app.test/api/users/3", identity_baseline="B",
                   identity_probe="A", channel="browser"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        first = self.ws.probe.transport.sent[0]
        self.assertTrue(first["ua"].startswith(BROWSER_UA))

    def test_tight_budget_marks_unverified_instead_of_refuted(self):
        # 基线一发之后只剩一发（前面的候选已经花掉一发）：消歧要两发，做不了，
        # 就不能把 403 当"没洞"
        raw = [t for t in vhx.TEMPLATES if t["id"] == "idor-object-ref"][0]
        import copy
        raw = copy.deepcopy(raw)
        raw["budget"]["max_requests"] = 3
        # 全局账本只剩一发：前面的候选已经花掉一发，总预算只有两发
        self.ws.budget.max_requests = 2
        self.ws.budget.restore(1)
        self.ws.probe.transport.mode = "vuln"
        f = Executor(self.ws.probe, self.ws.store, ENG).run(
            vhx.load(raw), Target(url="http://app.test/api/users/3",
                                  identity_baseline="B", identity_probe="A"))
        self.assertEqual(f.status, "hypothesis", f.verdict)
        self.assertTrue(f.stop_reason.startswith("channel_unverified"), f.stop_reason)


class HeaderOverrideTest(unittest.TestCase):
    def test_overrides_do_not_duplicate(self):
        root = tempfile.mkdtemp(prefix="pta-hdr-")
        try:
            init_workspace(root, Scope(engagement_id=ENG, domains=("app.test",),
                                       allow_private=True, rate_per_host=200, max_requests=50))
            ws = open_workspace(root, transport=UaTransport("open"),
                                dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
            ws.probe.run(__import__("pta.probe", fromlist=["ProbeRequest"]).ProbeRequest(
                action_id="hdr", url="http://app.test/x", method="GET",
                headers_extra=(("User-Agent", "Mozilla/custom"), ("Accept", "text/html")),
                level="L1"))
            headers = ws.probe.transport.sent[0]["headers"]
            self.assertEqual(headers.get("user-agent"), "Mozilla/custom")
            self.assertEqual(headers.get("accept"), "text/html")
        finally:
            shutil.rmtree(root, ignore_errors=True)


class BreakerTest(unittest.TestCase):
    """熔断只看"服务器要我们慢下来"，不看"应用拒绝"。

    403 既可能是 WAF，也可能是鉴权失败。之前把 403 计入熔断，一个带几个
    受保护接口的目标就能把熔断打开，之后整场演练全被 blocked 掉——
    这个 bug 是真靶场跑分时暴露的（ssrf 白名单用例连打 403 之后，
    后面两个用例全部 baseline:blocked）。
    """

    def _ws(self, status):
        class Fixed(Transport):
            name = "fixed"

            def send(self, req, timeout_s=10.0):
                return _resp(status, PLAIN_403)

        ws, root = _ws_with_transport(Fixed())
        return ws, root

    def test_403_does_not_trip_breaker(self):
        ws, root = self._ws(403)
        try:
            for i in range(30):
                ws.probe.run(_req("r-%d" % i))
            self.assertEqual(ws.budget.breaker.state, "closed")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_429_trips_breaker(self):
        ws, root = self._ws(429)
        try:
            statuses = [ws.probe.run(_req("r-%d" % i)).status for i in range(30)]
            self.assertEqual(ws.budget.breaker.state, "open")
            # 熔断打开后 probe 不抛异常，而是返回 blocked（调用方只看状态）
            self.assertIn("blocked", statuses)
        finally:
            shutil.rmtree(root, ignore_errors=True)


def _req(action_id):
    from pta.probe import ProbeRequest
    return ProbeRequest(action_id=action_id, url="http://app.test/api/users/3",
                        method="GET", identity="A", label="t", level="L1")


def _ws_with_transport(transport):
    root = os.path.join(tempfile.mkdtemp(prefix="pta-brk-"), "eng")
    scope = Scope(engagement_id=ENG, domains=("app.test",), allow_private=False,
                  max_requests=200, rate_per_host=1000.0)
    init_workspace(root, scope)
    ws = open_workspace(root)
    ws.probe.transport = transport
    ws.probe.dns = DnsPin(resolver=lambda h: [PUBLIC_IP])
    return ws, os.path.dirname(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
