"""通道消歧演示：同一个 403，可能是应用拒绝，也可能是 WAF 把我们当爬虫。

跑法：python demo_channels.py

问题背景：
  403/429/503 有两种成因——
    ① 应用层拒绝（真的没权限，这就是"无洞"的样子）
    ② 拦截层拦截（把我们当扫描器，洞可能就在后面，但被挡住了）
  只看一次请求分不出来。分不清的后果很具体：把"有洞但被 WAF 挡"记成
  refuted，报告上写着"已否定"，操作者再也不会回来看这个点了。

这一层做的判断：
  换客户端身份（原样 / 浏览器 UA / curl UA）重发同一条请求。
    · 三档都通          → open        拦截层不存在
    · 有通有拦          → waf         拦截层在挑客户端，被拦那档不能当证据
    · 三档都拦 + 有特征 → waf         拦截页/响应头里有 Cloudflare 之类指纹
    · 三档都拦 + 无特征 → app_denied  应用自己拒绝，403 本身是证据
    · 三档都错          → unreachable 连不上，不是洞的问题

  只有 waf 会让"被拦"变成"待验证"（0.5 分 hypothesis），
  app_denied 继续走原来的判定链（oracle 判 refuted）。

演示的站点是一个真 HTTP 服务，WAF 规则写在服务端：
  · UA 不像浏览器 → 403 + cf-ray 头 + Cloudflare 风格的拦截页
  · 带 SQL 载荷且 UA 不是浏览器 → 500（说明"放行了，洞是真的"）
  · /api/denied 任何时候都 403（模拟应用层鉴权）
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
sys.path.insert(0, HERE)

from pta import vhx  # noqa: E402
from pta.channels import ChannelProbe  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

ENG = "ENG-CHAN"

CF_PAGE = (
    b"<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title>"
    b"</head><body><h1>Sorry, you have been blocked</h1>"
    b"<div id='cf-error-details'>Cloudflare Ray ID: 8a1b2c3d4e5f</div></body></html>"
)
PLAIN_403 = b'{"error": "forbidden", "reason": "insufficient role"}'


class Site(BaseHTTPRequestHandler):
    """真 HTTP：WAF 规则在服务端，不在传输层。"""

    protocol_version = "HTTP/1.1"
    server_version = "ChanDemo/1.0"

    mode = "waf"          # waf | app_denied | open
    block_all = False     # 连浏览器 UA 也拦（演示"三档全拦"）
    hits = []

    def log_message(self, fmt, *args):  # 静音
        pass

    # ---------- 工具 ----------
    def _send(self, status, body, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _block(self):
        self._send(403, CF_PAGE,
                   {"cf-ray": "8a1b2c3d4e5f-SIN", "cf-mitigated": "challenge",
                    "Content-Type": "text/html"})

    def _ua(self):
        return self.headers.get("User-Agent", "")

    def _is_browser(self):
        return "Mozilla/5.0" in self._ua()

    # ---------- 路由 ----------
    def do_GET(self):
        Site.hits.append(self.path)
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        raw = (q.get("id") or ["1"])[0]

        if Site.block_all:
            self._block()
            return
        if self.mode == "app_denied" or parts.path == "/api/denied":
            # 应用层鉴权：跟 UA 无关，任何人都 403
            self._send(403, PLAIN_403)
            return
        if self.mode == "waf" and not self._is_browser():
            # 拦截层：只看客户端长相
            self._block()
            return
        if parts.path == "/api/items":
            if "'" in raw:
                body = (b'{"error": "sqlite3.OperationalError: unrecognized token: '
                        b'\'\\\'\\\'\\\'"}"')
                self._send(500, body)
                return
            self._send(200, b'{"items": [{"id": 1, "name": "widget"}]}')
            return
        self._send(404, b'{"error": "not found"}')


def _start():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


def _template(tid):
    return copy.deepcopy([t for t in vhx.TEMPLATES if t["id"] == tid][0])


def _ws(port, budget=30):
    root = os.path.join(tempfile.mkdtemp(prefix="pta-chan-"), "eng")
    init_workspace(root, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                               allow_private=True, allowed_ports=(port,),
                               max_requests=budget, rate_per_host=1000.0))
    ws = open_workspace(root)
    ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
    return ws, root


def main() -> int:
    httpd, port = _start()
    base = "http://127.0.0.1:%d" % port
    ws, root = _ws(port, budget=40)
    ok = []

    def show(title):
        print("\n" + title)
        print("-" * 78)

    try:
        # ① 直接问通道层：三档各自什么下场
        show("① 通道探针：%s/api/items?id=1（WAF 只放行浏览器 UA）" % base)
        Site.mode = "waf"
        report = ChannelProbe(ws.probe).run(base + "/api/items?id=1")
        for r in report.results:
            print("  %-8s status=%-3d blocked=%-5s markers=%s"
                  % (r.name, r.status, r.blocked, ",".join(r.markers) or "-"))
        print("  → verdict=%s  best=%s  requests=%d"
              % (report.verdict, report.best, report.requests))
        ok.append(("waf 场景判定为 waf 且给出可用档",
                   report.verdict == "waf" and report.best == "browser"))

        # ② 应用层拒绝：三档一致、无特征 → 不能叫"分不清"
        show("② 同一个探针打成应用层拒绝（/api/denied）")
        report2 = ChannelProbe(ws.probe).run(base + "/api/denied")
        for r in report2.results:
            print("  %-8s status=%-3d blocked=%-5s markers=%s"
                  % (r.name, r.status, r.blocked, ",".join(r.markers) or "-"))
        print("  → verdict=%s（403 本身是证据）" % report2.verdict)
        ok.append(("app_denied 与 waf 区分开", report2.verdict == "app_denied"))

        # ③ 执行器：载荷被拦 → 换档重发 → 拿到真 SQLite 报错
        show("③ 执行器：基线被拦，换浏览器档后拿到 500 + sqlite 签名")
        Site.hits.clear()
        f = Executor(ws.probe, ws.store, ENG).run(
            vhx.load(_template("sqli-error-boolean")),
            Target(url=base + "/api/items?id=1", param_path="query:id",
                   identity_baseline="A", identity_probe="A"))
        chan = (f.verdict.get("metrics") or {}).get("channel") or {}
        print("  status=%s confidence=%.3f  stop=%s"
              % (f.status, f.confidence, f.stop_reason or "-"))
        print("  理由：%s" % f.verdict.get("rationale", ""))
        print("  通道：verdict=%s best=%s 探针请求=%s"
              % (chan.get("verdict"), chan.get("best"), chan.get("requests")))
        print("  证据：%d 条（含三档通道证据）" % len(f.evidence_ids))
        ok.append(("换档后判出真洞", f.status == "confirmed" and chan.get("best") == "browser"))

        # ④ 三档全拦：既不说有洞，也不说没洞
        show("④ 三档全拦（连浏览器 UA 也 403 + cf-ray）")
        Site.block_all = True
        f4 = Executor(ws.probe, ws.store, ENG).run(
            vhx.load(_template("idor-object-ref")),
            Target(url=base + "/api/users?id=1", param_path="query:id",
                   identity_baseline="A", identity_probe="B", id_plus_one="1"))
        print("  status=%s confidence=%.3f  stop=%s"
              % (f4.status, f4.confidence, f4.stop_reason or "-"))
        print("  理由：%s" % f4.verdict.get("rationale", ""))
        ok.append(("全拦记为待验证而不是已否定",
                   f4.status == "hypothesis" and (f4.stop_reason or "").startswith("channel_blocked")))
        Site.block_all = False

        # ⑤ 预算不够消歧：宁可"未验证"，也不许判否
        show("⑤ 预算只够基线一发：不做消歧，也不把 403 当没洞")
        ws2, root2 = _ws(port, budget=3)
        try:
            raw = _template("idor-object-ref")
            raw["budget"]["max_requests"] = 3
            # 账本已经花掉 2 发，只剩 1 发：刚好够基线，不够做三档消歧
            ws2.budget.restore(2)
            Site.mode = "waf"
            f5 = Executor(ws2.probe, ws2.store, ENG).run(
                vhx.load(raw),
                Target(url=base + "/api/items?id=1", param_path="query:id",
                       identity_baseline="A", identity_probe="B"))
            print("  status=%s confidence=%.3f  stop=%s"
                  % (f5.status, f5.confidence, f5.stop_reason or "-"))
            print("  请求数=%d（模板上限 3，可用 1）" % f5.requests_used)
            ok.append(("预算不足标 unverified",
                       f5.status == "hypothesis"
                       and (f5.stop_reason or "").startswith("channel_unverified")))
        finally:
            shutil.rmtree(os.path.dirname(root2), ignore_errors=True)

        print("\n" + "=" * 78)
        print("自检：")
        for name, passed in ok:
            print("  %s %s" % ("OK  " if passed else "FAIL", name))
        bad = [n for n, p in ok if not p]
        print("\n结果：%s" % ("OK（403 的两种成因能分开；分不清时不判否）"
                              if not bad else "FAIL（%s）" % ", ".join(bad)))
        return 0 if not bad else 1
    finally:
        httpd.shutdown()
        httpd.server_close()
        shutil.rmtree(os.path.dirname(root), ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
