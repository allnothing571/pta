"""重定向跟随：相对地址、query、片段、以及"跟不过去时留下什么"。

这个文件是真实踩坑留下的：WebGoat 302 给的是 `http://127.0.0.1/WebGoat/start.mvc`
（站点自己拼绝对地址时把 8080 丢了），原来把 Location 原样交给 check_request，
于是相对地址直接炸、绝对地址把我们带去 80 口，整次爬取只剩一行 fetch_failed。
"""
from __future__ import annotations

import unittest

from pta.models import RawResponse
from pta.probe import ProbeRequest
from pta.recon import Recon
from pta.scope import Scope
from pta.transport import Transport, TransportError
from pta.workspace import init_workspace, open_workspace

from support import WorkspaceCase, fake_dns

HTML = (("Content-Type", "text/html; charset=utf-8"),)


def _resp(status, headers=HTML, body=b"<html><body>ok</body></html>"):
    t = 1000.0
    return RawResponse(status=status, reason="OK", http_version="HTTP/1.1",
                       headers=tuple(headers), body=body,
                       t_send=t, t_first_byte=t, t_end=t)


class Scripted(Transport):
    """按顺序回放的假服务器：一项一个响应，可以是异常。"""

    name = "scripted"

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    def send(self, req, timeout_s: float = 10.0) -> RawResponse:
        self.sent.append(req)
        if not self.replies:
            return _resp(200)
        item = self.replies.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _get(ws, url, **kw):
    return ws.probe.run(ProbeRequest(action_id="rd-%d" % len(ws.store.list_evidence("ENG-T")),
                                     url=url, method="GET", identity="A",
                                     label="recon", level="L1", follow_redirects=True, **kw))


def make_ws_with_ports(case, replies, ports=(80, 443, 8080), domains=("app.test",)):
    """Scope 是 frozen 的，端口只能建的时候给——本地靶场就是这么开的。"""
    scope = Scope(engagement_id="ENG-T", domains=tuple(domains), allow_private=True,
                  rate_per_host=1000.0, max_requests=5000, allowed_ports=tuple(ports))
    init_workspace(case.tmp, scope)
    ws = open_workspace(case.tmp, transport=Scripted(replies), dns=fake_dns())
    ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
    return ws


class RedirectFollowTest(WorkspaceCase):
    def _ws(self, replies, ports=(80, 443, 8080)):
        return make_ws_with_ports(self, replies, ports=ports)

    def test_relative_location_resolves_on_the_same_origin(self):
        ws = self._ws([_resp(302, (("Location", "/login"),)), _resp(200)])
        res = _get(ws, "http://app.test:8080/box")
        self.assertEqual(res.status, "ok")
        self.assertEqual(len(ws.transport.sent), 2)
        second = ws.transport.sent[1]
        self.assertEqual((second.host, second.port, second.raw_path),
                         ("app.test", 8080, "/login"))
        self.assertEqual(res.redirects, ("http://app.test:8080/login",))

    def test_relative_location_climbs_one_level(self):
        ws = self._ws([_resp(302, (("Location", "../admin"),)), _resp(200)])
        _get(ws, "http://app.test:8080/a/b")
        self.assertEqual(ws.transport.sent[1].raw_path, "/admin")

    def test_location_query_is_kept(self):
        ws = self._ws([_resp(302, (("Location", "/login?continue=/home&x=1"),)), _resp(200)])
        _get(ws, "http://app.test:8080/box")
        self.assertEqual(ws.transport.sent[1].query, (("continue", "/home"), ("x", "1")))

    def test_fragment_is_not_sent(self):
        ws = self._ws([_resp(302, (("Location", "/start#/lesson/x"),)), _resp(200)])
        res = _get(ws, "http://app.test:8080/box")
        self.assertEqual(ws.transport.sent[1].raw_path, "/start")
        self.assertEqual(res.redirects, ("http://app.test:8080/start",))

    def test_absolute_location_without_port_is_followed_as_written(self):
        # 站点自己丢了端口：我们照它说的走（不偷偷改端口），连不上就记一笔。
        ws = self._ws([_resp(302, (("Location", "http://app.test/start"),)),
                       TransportError("连接 app.test:80 失败")])
        res = _get(ws, "http://app.test:8080/box")
        self.assertEqual(res.status, "ok")            # 302 本身是有效证据
        self.assertEqual(ws.transport.sent[1].port, 80)
        self.assertTrue(res.redirect_blocked.startswith("http://app.test/start|"))

    def test_unreachable_hop_does_not_raise(self):
        ws = self._ws([_resp(302, (("Location", "/next"),)),
                       TransportError("连接 app.test:8080 失败：refused")])
        res = _get(ws, "http://app.test:8080/box")
        self.assertEqual(res.status, "ok")
        self.assertIsNotNone(res.evidence_id)
        self.assertIn("refused", res.redirect_blocked)

    def test_out_of_scope_hop_is_recorded_as_blocked(self):
        ws = self._ws([_resp(302, (("Location", "http://evil.test/x"),))])
        res = _get(ws, "http://app.test:8080/box")
        self.assertEqual(res.status, "ok")
        self.assertEqual(len(ws.transport.sent), 1)   # 越界的那跳一次都没发
        self.assertIn("evil.test", res.redirect_blocked)

    def test_hop_limit_still_applies(self):
        replies = [_resp(302, (("Location", "/r%d" % i),)) for i in range(5)]
        ws = self._ws(replies + [_resp(200)])
        res = _get(ws, "http://app.test:8080/box", max_hops=2)
        self.assertEqual(len(res.redirects), 2)

    def test_blocked_redirect_reaches_the_action_log(self):
        ws = self._ws([_resp(302, (("Location", "http://evil.test/x"),))])
        _get(ws, "http://app.test:8080/box")
        rows = [r for r in ws.store.logs("ENG-T") if r["tool"] == "http_probe"]
        self.assertTrue(rows)
        self.assertTrue(any("evil.test" in (r["detail_json"] or "") for r in rows))


class ReconRedirectTest(WorkspaceCase):
    def _ws(self, replies, ports=(80, 443, 8080)):
        return make_ws_with_ports(self, replies, ports=ports)

    def test_page_records_where_it_landed(self):
        ws = self._ws([_resp(302, (("Location", "/start"),)), _resp(200)])
        report = Recon(ws, max_pages=2, identity="A").run(["http://app.test:8080/box"])
        self.assertEqual(len(report.pages), 1)
        self.assertEqual(report.pages[0].url, "http://app.test:8080/box")
        self.assertEqual(report.pages[0].final_url, "http://app.test:8080/start")
        self.assertEqual(report.pages[0].to_json()["final_url"], "http://app.test:8080/start")

    def test_blocked_redirect_lands_in_the_report(self):
        ws = self._ws([_resp(302, (("Location", "http://app.test/start"),)),
                       TransportError("连接 app.test:80 失败")])
        report = Recon(ws, max_pages=2, identity="A").run(["http://app.test:8080/box"])
        self.assertEqual(len(report.blocked_redirects), 1)
        self.assertEqual(report.blocked_redirects[0]["target"], "http://app.test/start")
        self.assertIn("80", report.blocked_redirects[0]["reason"])
        self.assertEqual(report.to_json()["counts"]["blocked_redirects"], 1)


if __name__ == "__main__":
    unittest.main()
