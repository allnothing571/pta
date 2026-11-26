"""真实 socket 端到端检查：不经过 MockTransport，验证 DnsPin + DirectPinnedTransport。

起一个本地静态服务器（含 /.git/HEAD），用真实 TCP 跑一次 info-disclosure 模板。
python live_check.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pta import vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def main() -> int:
    site = tempfile.mkdtemp(prefix="pta-site-")
    os.makedirs(os.path.join(site, ".git"))
    with open(os.path.join(site, ".git", "HEAD"), "w", encoding="utf-8") as fh:
        fh.write("ref: refs/heads/main\n")
    handler = partial(Quiet, directory=site)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_port
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("本地靶站：http://127.0.0.1:%d  （/.git/HEAD 可读）" % port)

    root = tempfile.mkdtemp(prefix="pta-live-")
    scope = Scope(engagement_id="LIVE-1", domains=("127.0.0.1",), allow_private=True,
                  rate_per_host=50, max_requests=50, allowed_ports=(80, 443, port))
    init_workspace(root, scope)
    ws = open_workspace(root)  # transport=None → build_transport → DirectPinnedTransport
    print("transport：%s" % ws.transport.name)

    tpl = {t["id"]: t for t in vhx.TEMPLATES}["info-disclosure-artifact"]
    f = Executor(ws.probe, ws.store, "LIVE-1").run(
        vhx.load(tpl), Target(url="http://127.0.0.1:%d/.git/HEAD" % port))
    print(json.dumps(f.to_json(), ensure_ascii=False, indent=2))

    rep = ws.replayer.replay(f.evidence_ids[0])
    print("replay：match=%s status=%s" % (rep["match"], rep.get("actual_status")))

    # 反证：端口未放行时被 Scope 拦住
    bad = Executor(ws.probe, ws.store, "LIVE-1").run(
        vhx.load(tpl), Target(url="http://127.0.0.1:%d/.git/HEAD" % (port + 1)))
    denied = ws.store.logs("LIVE-1", "denied")
    print("端口越界：status=%s denied_log=%d" % (bad.stop_reason or bad.status, len(denied)))

    httpd.shutdown()
    ok = f.status == "confirmed" and rep["match"] and len(denied) >= 1

    # ---------- 第二阶段：真实 SSRF + 真实 OOB 回连 ----------
    ssrf_ok = _ssrf_stage()

    print("\n真实链路：%s（含 SSRF 带外）" % ("OK" if ok and ssrf_ok else "FAIL"))
    for d in (site, root):
        shutil.rmtree(d, ignore_errors=True)
    return 0 if (ok and ssrf_ok) else 1


class _SsrfTarget(ThreadingHTTPServer):
    """一个真的会去请求 url 参数的服务端——最小 SSRF 夹具。"""


def _ssrf_stage() -> bool:
    import urllib.parse
    import urllib.request

    from pta.oob import OobCollector

    oob = OobCollector(public_host="127.0.0.1", bind_host="127.0.0.1").start()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            url = (qs.get("url") or [""])[0]
            body = b"no url"
            status = 400
            if url:
                try:
                    with urllib.request.urlopen(url, timeout=3) as r:
                        body = b"fetched %d" % r.status
                    status = 200
                except Exception as exc:  # 目标端请求失败也要如实返回
                    body = ("fetch failed: %s" % exc).encode()
                    status = 502
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    target = _SsrfTarget(("127.0.0.1", 0), Handler)
    tport = target.server_port
    threading.Thread(target=target.serve_forever, daemon=True).start()
    print("\nSSRF 夹具：http://127.0.0.1:%d/?url=  （会把 url 参数取回来）" % tport)
    print("OOB 收集器：http://127.0.0.1:%d/  DNS udp/%d" % (oob.http_port, oob.dns_port))

    root = tempfile.mkdtemp(prefix="pta-ssrf-")
    scope = Scope(engagement_id="LIVE-2", domains=("127.0.0.1",), allow_private=True,
                  rate_per_host=20, max_requests=20,
                  allowed_ports=(80, 443, tport, oob.http_port))
    init_workspace(root, scope)
    ws = open_workspace(root, oob=oob)
    ws.gate.decide("LIVE-2", "http_probe", "127.0.0.1", "query:url", "oob_url", "L2",
                   "approve", scope="class", note="live")

    tpl = {t["id"]: t for t in vhx.TEMPLATES}["ssrf-outbound"]
    f = Executor(ws.probe, ws.store, "LIVE-2").run(
        vhx.load(tpl),
        Target(url="http://127.0.0.1:%d/?url=placeholder" % tport,
               param_path="query:url", oob_wait_s=2.0))
    callbacks = [tok for tok in oob.tokens() if tok["callbacks"]]
    print("SSRF：status=%s confidence=%.3f 证据=%d 回连 token=%d" % (
        f.status, f.confidence, len(f.evidence_ids), len(callbacks)))
    print("     回连明细：%s" % [oob.check(t["token"])[0].to_json() for t in callbacks])

    target.shutdown()
    oob.stop()
    for d in (root,):
        shutil.rmtree(d, ignore_errors=True)
    return f.status == "confirmed"


if __name__ == "__main__":
    sys.exit(main())
