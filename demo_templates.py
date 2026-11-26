"""P1 新增两条模板的演示：path-traversal-lfi / open-redirect（含反例）。

python demo_templates.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pta import vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.models import RawResponse  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import Transport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
PASSWD = b"root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
NOT_FOUND = b"<!doctype html><html><body><h1>404 Not Found</h1></body></html>"
SPA = b'<!doctype html><html><body><div id="root"></div></body></html>'


class Shop(Transport):
    """按参数值决定响应的靶站：只有真带载荷时才"读得到文件/跳得出去"。"""

    name = "demo-shop"

    def __init__(self, mode):
        self.mode = mode
        self.sent = []

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        q = unquote_plus("&".join("%s=%s" % (k, v) for k, v in req.query))
        if "traversal" in self.mode:
            if self.mode == "traversal-safe":
                # safe：路径不信输入，直接 404
                return RawResponse(status=404, reason="Not Found", http_version="HTTP/1.1",
                                   headers=(("Content-Type", "text/html"),), body=NOT_FOUND,
                                   t_send=0.0, t_first_byte=0.0, t_end=0.0)
            if "etc/passwd" in q or "win.ini" in q:
                # vulnerable：直接拼路径
                return RawResponse(status=200, reason="OK", http_version="HTTP/1.1",
                                   headers=(("Content-Type", "text/plain"),), body=PASSWD,
                                   t_send=0.0, t_first_byte=0.0, t_end=0.0)
            return RawResponse(status=404, reason="Not Found", http_version="HTTP/1.1",
                               headers=(("Content-Type", "text/html"),), body=NOT_FOUND,
                               t_send=0.0, t_first_byte=0.0, t_end=0.0)
        # redirect 模式
        if "redirect.test" in q:
            if self.mode == "redirect-vuln":
                return RawResponse(status=302, reason="Found", http_version="HTTP/1.1",
                                   headers=(("Location", "https://redirect.test/open"),),
                                   body=b"", t_send=0.0, t_first_byte=0.0, t_end=0.0)
            # safe：站内白名单，外部地址被改写回首页
            return RawResponse(status=302, reason="Found", http_version="HTTP/1.1",
                               headers=(("Location", "/home"),), body=b"",
                               t_send=0.0, t_first_byte=0.0, t_end=0.0)
        return RawResponse(status=200, reason="OK", http_version="HTTP/1.1",
                           headers=(("Content-Type", "text/html"),), body=SPA,
                           t_send=0.0, t_first_byte=0.0, t_end=0.0)


def tpl(tid):
    return vhx.load({t["id"]: t for t in vhx.TEMPLATES}[tid])


def make(mode):
    root = tempfile.mkdtemp(prefix="pta-demo-tpl-")
    init_workspace(root, Scope(engagement_id="DEMO-TPL", domains=("shop.test",),
                               allow_private=True, rate_per_host=200, max_requests=200))
    ws = open_workspace(root, transport=Shop(mode),
                        dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
    return root, ws


CASES = [
    ("path-traversal-lfi", "traversal-vuln", "下载接口拼路径（应确认）",
     Target(url="http://shop.test/download?file=report.pdf", param_path="query:file")),
    ("path-traversal-lfi", "traversal-safe", "路径被规范化（应否定）",
     Target(url="http://shop.test/download?file=report.pdf", param_path="query:file")),
    ("open-redirect", "redirect-vuln", "外链跳走（应确认）",
     Target(url="http://shop.test/login?next=/home", param_path="query:next")),
    ("open-redirect", "redirect-safe", "白名单改写回首页（应否定）",
     Target(url="http://shop.test/login?next=/home", param_path="query:next")),
]


def main() -> int:
    print("%-24s %-12s %-6s %-6s %s" % ("模板", "结论", "置信度", "请求", "场景"))
    print("-" * 88)
    bad = 0
    for tid, mode, note, target in CASES:
        root, ws = make(mode)
        try:
            f = Executor(ws.probe, ws.store, "DEMO-TPL").run(tpl(tid), target)
            print("%-24s %-12s %-6.3f %-6d %s" % (tid, f.status, f.confidence,
                                                 f.requests_used, note))
            want = "confirmed" if "vuln" in mode else "refuted"
            if f.status != want:
                bad += 1
                print("   ！预期 %s，实际 %s：%s" % (want, f.status, f.verdict.get("rationale")))
        finally:
            shutil.rmtree(root, True)

    loaded = sorted(t["id"] for t in vhx.TEMPLATES)
    print("\n已加载模板 %d 个：%s" % (len(loaded), ", ".join(loaded)))
    print("结果：%s" % ("OK（正例确认、反例否定）" if not bad else "FAIL（%d 条不符预期）" % bad))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
