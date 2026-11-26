"""第 5–8 项演示：写方法自动候选 / 上传 RCE / XXE / 反序列化标记。

四段的共同点：**判的不是"服务器回了什么"，而是"这个回应对应哪种缺口"**。
- 写方法候选：只有页面自己用 POST/PUT/PATCH 打过，才提"改写对象"；
- 上传：文件被接受(201) → 能被取回(200) → 能当脚本执行，三段各有各的分；
- XXE：没有回连就是没有，解析器不去取实体，你写多漂亮的 XML 都没用；
- 反序列化：报错里有框架痕迹只证明"入口吃这个格式"，最高 0.80，不写 RCE。

跑法：python demo_schema.py
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import payloads, vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.models import verdict_status  # noqa: E402
from pta.oob import OobCollector  # noqa: E402
from pta.planner import Asset, PlannerState, heuristic_candidates  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockRoute, MockTransport, RawResponse, Transport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-DEMO-SCHEMA"


def new_ws(root, transport, oob=None):
    shutil.rmtree(root, ignore_errors=True)
    init_workspace(root, Scope(engagement_id=ENG, domains=("app.test",), allow_private=True,
                               rate_per_host=200, max_requests=200))
    return open_workspace(root, transport=transport, oob=oob,
                          dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))


def tpl(tid):
    return vhx.load([t for t in vhx.TEMPLATES if t["id"] == tid][0])


def ok(resp_status, body, ctype="application/json"):
    t0 = time.perf_counter()
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    return RawResponse(status=resp_status, reason="OK", http_version="HTTP/1.1",
                       headers=(("Content-Type", ctype),), body=raw,
                       t_send=t0, t_first_byte=t0, t_end=t0 + 0.002)


# ---------------------------------------------------------------- ① Planner
def section_planner():
    print("① 写方法自动候选（harvest 见过 POST，才提'改写对象'）")
    assets = [
        Asset(url="http://app.test/api/v2/profile", method="POST", status=201,
              content_type="application/json", body_params=("displayName", "role")),
        Asset(url="http://app.test/api/v2/orders/9", method="PATCH", status=204,
              content_type="application/json"),
        Asset(url="http://app.test/api/v2/search?q=x", method="GET", status=200,
              content_type="application/json"),
    ]
    state = PlannerState(engagement_id=ENG, domains=("app.test",), assets=assets,
                         findings=[], budget={"used": 0, "max": 200},
                         templates=list(vhx.TEMPLATES))
    cands = heuristic_candidates(state)
    for c in cands:
        print("   %-28s %-6s %-11s %.2f  %s"
              % (c.template_id, c.method, c.param_path, c.priority, c.rationale))
    writes = [c for c in cands if c.template_id == "idor-write-object"]
    assert writes, "POST 资产应产生写入候选"
    assert all(c.method in ("POST", "PUT", "PATCH") for c in writes), "写入候选必须继承写方法"
    assert not [c for c in cands
                if (c.param_path or "").startswith("body:") and c.method == "GET"]
    print("   → GET 那条没出写入候选（同名字段在 GET 上是查询条件，不是可写字段）")
    return True


# ---------------------------------------------------------------- ② 上传
class UploadSite(Transport):
    def __init__(self, mode):
        self.mode = mode
        self.sent = []
        self.files = {}

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        path, method = req.raw_path.split("?", 1)[0], req.method.upper()
        if path == "/api/upload" and method == "POST":
            if self.mode == "deny":
                return ok(403, '{"error":"forbidden"}')
            if self.mode == "no_store":
                return ok(201, '{"ok":true}')
            self.files[payloads.upload_file_name()] = (req.body or b"", req.headers)
            return ok(201, '{"ok":true}')
        if path.startswith("/uploads/") and method == "GET":
            hit = self.files.get(path.rsplit("/", 1)[-1])
            if hit:
                ctype = "text/plain" if self.mode == "plain" else "text/html"
                return ok(200, hit[0], ctype)
        return ok(404, "not found", "text/plain")


def section_upload(root):
    print()
    print("② 文件上传：被接受 ≠ 能被取回 ≠ 能当脚本执行")
    rows = []
    for mode, label in (("vuln", "回读为 text/html"), ("plain", "回读为 text/plain"),
                        ("no_store", "201 但没落盘"), ("deny", "上传被拒 403")):
        site = UploadSite(mode)
        ws = new_ws(root, site)
        ws.gate.decide(ENG, "http_probe", "app.test", "body:file", "upload_shell", "L2",
                       "approve", scope="class")
        f = Executor(ws.probe, ws.store, ENG).run(
            tpl("upload-rce"),
            Target(url="http://app.test/api/upload", method="POST", param_path="body:file",
                   verify_url="http://app.test/uploads/%s" % payloads.upload_file_name()))
        rows.append((label, f.status, f.confidence, f.verdict.get("rationale", "")))
        print("   %-18s %-10s %.3f  %s" % (label, f.status, f.confidence,
                                           f.verdict.get("rationale", "")))
    assert rows[0][2] >= 0.95, "可执行回读应给 0.95"
    assert 0.85 <= rows[1][2] < rows[0][2], "不可执行回读应低一档"
    assert rows[2][2] <= 0.15 and rows[3][2] == 0.0
    return True


# ---------------------------------------------------------------- ③ XXE
class XxeSite(Transport):
    def __init__(self, collector, parse=True):
        self.collector = collector
        self.parse = parse
        self.sent = []

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        body = (req.body or b"").decode("latin-1")
        if self.parse and "<!ENTITY" in body:
            m = re.search(r'SYSTEM "([^"]+)"', body)
            if m:
                token = m.group(1).rstrip("/").rsplit("/", 1)[-1]
                self.collector.inject(token, protocol="http", source_ip="198.51.100.7")
        return ok(200, '{"ok":true}')


def section_xxe(root):
    print()
    print("③ XXE：解析器去取实体才有回连，不取就没有")
    for parse, label in ((True, "解析器解析 DTD"), (False, "不解析外部实体")):
        oob = OobCollector(public_host="127.0.0.1", bind_host="127.0.0.1").start()
        try:
            site = XxeSite(oob, parse=parse)
            ws = new_ws(root, site, oob=oob)
            ws.gate.decide(ENG, "http_probe", "app.test", "body:xml", "xxe_entity", "L2",
                           "approve", scope="class")
            f = Executor(ws.probe, ws.store, ENG).run(
                tpl("xxe-entity"),
                Target(url="http://app.test/api/import", method="POST", param_path="body:xml",
                       oob_wait_s=1.0))
            entity = re.search(r'SYSTEM "([^"]+)"', (site.sent[-1].body or b"").decode("latin-1"))
            print("   %-16s %-10s %.3f  实体=%s"
                  % (label, f.status, f.confidence, entity.group(1) if entity else "—"))
            if parse:
                assert f.status == "confirmed", f.verdict
                assert entity and "/t/" in entity.group(1), "实体 URL 必须带本次 token"
            else:
                assert f.status == "refuted" and f.confidence == 0.0
        finally:
            oob.stop()
    return True


# ---------------------------------------------------------------- ④ 反序列化
class DeserSite(Transport):
    def __init__(self, mode):
        self.mode = mode
        self.sent = []

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        if req.method.upper() == "POST" and (req.body or b"").startswith(b"\xac\xed\x00\x05"):
            if self.mode == "framework":
                return ok(500, '{"error":"java.io.InvalidClassException: pta"}')
            return ok(500, '{"error":"internal error"}')
        return ok(200, '{"ok":true}')


def section_deser(root):
    print()
    print("④ 反序列化：框架报错只证明入口存在，不证明有 gadget")
    for mode, label in (("framework", "框架异常"), ("generic", "通用 500")):
        site = DeserSite(mode)
        ws = new_ws(root, site)
        f = Executor(ws.probe, ws.store, ENG).run(
            tpl("deserialization-marker"),
            Target(url="http://app.test/api/import", method="POST", param_path="body:data"))
        sent = [r for r in site.sent if (r.body or b"").startswith(b"\xac\xed\x00\x05")]
        print("   %-10s %-10s %.3f  载荷字节=%s  状态=%s"
              % (label, f.status, f.confidence,
                 (sent[0].body[:4].hex() if sent else "—"), verdict_status(f.confidence)))
        if mode == "framework":
            assert f.status == "hypothesis" and f.confidence == 0.80
        else:
            assert f.status == "refuted"
    return True


def main():
    root = os.path.join(tempfile.gettempdir(), "pta-demo-schema")
    print("=" * 78)
    print("第 5–8 项：写方法候选 / 上传 / XXE / 反序列化")
    print("=" * 78)
    try:
        good = [section_planner(), section_upload(root), section_xxe(root),
                section_deser(root)]
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print()
    print("结果：%s（写入候选只在 harvest 见过写方法时出现；上传分三档；"
          "XXE 靠回连；反序列化只写到'入口存在'）" % ("OK" if all(good) else "FAIL"))
    return 0 if all(good) else 1


if __name__ == "__main__":
    sys.exit(main())
