"""SSRF 打进内网服务：靠回显指纹判定，不靠回连。

跑法：python demo_ssrf.py
场景：元数据服务 / Docker API / 参数没生效 / 应用把页面重写 / 内网地址黑名单 / 单特征
      + 未审批不出网
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from urllib.parse import unquote_plus

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import vhx
from pta.critic import Critic
from pta.executor import Executor, Target
from pta.scope import DnsPin, Scope
from pta.transport import MockTransport, RawResponse
from pta.workspace import init_workspace, open_workspace

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-SSRF"
APP_PAGE = b"<html><body><h1>fetch</h1><a href='/home'>home</a></body></html>"
METADATA = (b"ami-id\nami-launch-index\nami-manifest-path\nhostname\ninstance-action\n"
            b"instance-id\ninstance-type\nlocal-hostname\nplacement/\nsecurity-credentials/\n")
DOCKER = json.dumps({"ApiVersion": "1.41", "MinAPIVersion": "1.12", "GitCommit": "v20.10.7"},
                    sort_keys=True).encode()
ETCD = json.dumps({"etcdserver": "3.5.10", "etcdcluster": "3.5.0"}, sort_keys=True).encode()


class Gateway(MockTransport):
    """GET /fetch?url=… 由服务端去取，像无数个真实"图片代理 / 抓取接口"。"""

    def __init__(self, mode="vuln"):
        super().__init__([])
        self.mode = mode
        self.fetches = 0

    def _fetch(self, url):
        self.fetches += 1
        if self.mode == "docker_only":
            if url.startswith("http://127.0.0.1:2375"):
                return 200, DOCKER
            return 502, b"upstream failed"
        if url.startswith("http://169.254.169.254"):
            return 200, METADATA
        if url.startswith("http://127.0.0.1:2375"):
            return 200, DOCKER
        if url.startswith("http://127.0.0.1:2379"):
            return 200, ETCD
        return 502, b"upstream failed"

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        t0 = time.perf_counter()
        url = ""
        for k, v in req.query:
            if k == "url":
                url = unquote_plus(v)
        status, body = 200, APP_PAGE
        if self.mode == "rewrite":
            # 应用把任何抓取结果都重写成自己的模板，模板里带着第三方组件文案 ——
            # 关键点：**基线请求也会**拿到这页，所以能靠"基线不干净"识破。
            status, body = 200, (b'<html>cluster_name=lucene_version='
                                 b'You Know, for Search</html>')
        elif url:
            if self.mode == "deny":
                status, body = 403, b'{"error":"private address blocked"}'
            elif self.mode == "ignore":
                status, body = 200, APP_PAGE
            elif self.mode == "single":
                status, body = 200, b'{"platform":"linux"}'
            else:
                status, body = self._fetch(url)
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "text/html"),), body=body,
                           t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


def template():
    raw = [t for t in vhx.TEMPLATES if t["id"] == "ssrf-internal-service"][0]
    return vhx.load(raw)


def run_case(name, mode, expect, note, approve=True):
    root = tempfile.mkdtemp(prefix="pta-demo-ssrf-")
    init_workspace(root, Scope(engagement_id=ENG, domains=("app.test",), allow_private=True,
                               rate_per_host=200, max_requests=200))
    ws = open_workspace(root, transport=Gateway(mode),
                        dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
    if approve:
        for cls in ("internal_metadata_url", "internal_docker_url", "internal_etcd_url"):
            ws.gate.decide(ENG, "http_probe", "app.test", "query:url", cls, "L2",
                           "approve", scope="class")
    eng = Executor(ws.probe, ws.store, ENG)
    target = Target(url="http://app.test/fetch", param_path="query:url",
                    identity_baseline="none", identity_probe="none")
    f = eng.run(template(), target)
    crit = Critic(ws).review_finding(f, apply=False)
    ok = f.status == expect
    print("%-11s %-17s %-6.3f  %-5s  %s  %s" % (
        name, f.status, f.confidence, crit.status, "OK" if ok else "FAIL", note))
    if f.status == "confirmed":
        m = f.verdict["metrics"]
        print("            打到 %s，命中 %d 个特征：%s" % (
            m["service"], m["markers_count"], "、".join(m["markers_found"][:4])))
    elif approve:
        print("            %s" % f.verdict["rationale"])
    return ok, ws


def main():
    print("=== SSRF 内网服务指纹（回显证据，不依赖回连）===\n")
    print("%-11s %-17s %-6s  %-5s  %s  %s" % ("场景", "结论", "置信度", "Critic", "", "说明"))
    print("-" * 100)
    cases = [
        ("metadata", "vuln", "confirmed", "参数把请求打到云元数据服务"),
        ("docker", "docker_only", "confirmed", "127.0.0.1:2375 的 Docker API"),
        ("ignore", "ignore", "refuted", "参数没进 URL，回显就是页面本身"),
        ("rewrite", "rewrite", "refuted", "应用重写响应，页里本来就有这些词（基线也不干净）"),
        ("deny", "deny", "refuted", "内网地址黑名单（403）"),
        ("single", "single", "refuted", "只命中 1 个特征，判为待验证"),
        ("unapproved", "vuln", "pending_approval", "未审批：一次内网请求都不发"),
    ]
    good = True
    for name, mode, expect, note in cases:
        ok, ws = run_case(name, mode, expect, note, approve=(name != "unapproved"))
        if name == "unapproved":
            print("            实际发出的内网请求：%d" % ws.probe.transport.fetches)
            ok = ok and ws.probe.transport.fetches == 0
        good = good and ok

    print("\n结果：%s（元数据/Docker→确认；参数没生效/重写/黑名单/单特征→判否；未审批不出网）"
          % ("OK" if good else "FAIL"))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
