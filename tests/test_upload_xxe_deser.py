"""文件上传 / XXE / 反序列化标记（第 6–8 项）。

三条都是"整体替换请求体"的载荷：载荷自己决定 Content-Type，probe 不再往
query/JSON 字段里塞东西。判定的分野在于：
- 上传：文件被接受 != 能被取回，能被取回 != 能当脚本执行（0.95 / 0.88 两档）；
- XXE：必须有回连，解析器没去取实体就是没有；
- 反序列化：错误信息里出现序列化框架的痕迹只能证明"入口吃这个格式"，
  不能证明有可用 gadget，所以最高只给 0.80（hypothesis）。
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta import payloads, vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.models import verdict_status  # noqa: E402
from pta.oob import OobCollector  # noqa: E402
from pta.oracles import (  # noqa: E402
    DeserializationMarkerPresent, Observation, ORACLE_REGISTRY, UploadReadback,
)
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockRoute, MockTransport, RawResponse, Transport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-U"


def obs(role, body, status=200, identity="A", method="POST", ctype="text/plain"):
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    return Observation(role=role, evidence_id="ev-%s-%s" % (role, status), identity=identity,
                       method=method, url="http://app.test/api/upload", status=status,
                       content_type=ctype, body_sha256="%064x" % (status + len(raw)),
                       body_len=len(raw), body=raw, headers=(("Content-Type", ctype),))


class UploadOracleTest(unittest.TestCase):
    def verdict(self, roles, **kw):
        o = ORACLE_REGISTRY["upload_readback"]()
        return o.run(roles, o.Args(**kw))

    def test_readback_as_html_confirms(self):
        v = self.verdict([obs("probe", '{"ok":true}', 201),
                          obs("verify", "<script>document.title='ptaab12cd34'</script>", 200,
                              ctype="text/html")])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.95)
        self.assertEqual(verdict_status(v.confidence), "confirmed")

    def test_readback_but_not_executable(self):
        v = self.verdict([obs("probe", '{"ok":true}', 201),
                          obs("verify", "ptaab12cd34", 200, ctype="text/plain")])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.88)
        self.assertIn("不成立", v.rationale)

    def test_missing_readback_is_not_evidence(self):
        v = self.verdict([obs("probe", '{"ok":true}', 201)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("verify", v.missing_evidence)

    def test_upload_denied(self):
        v = self.verdict([obs("probe", "no", 403),
                          obs("verify", "ptaab12cd34", 200, ctype="text/html")])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)

    def test_upload_accepted_but_404_on_readback(self):
        v = self.verdict([obs("probe", '{"ok":true}', 201),
                          obs("verify", "not found", 404)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.15)

    def test_echo_is_not_landing(self):
        # 上传响应里回显了标记、回读却取不到：这是"回显"，不是"落地"
        v = self.verdict([obs("probe", "ptaab12cd34", 201),
                          obs("verify", "not found", 404)])
        self.assertFalse(v.passed)
        self.assertIn("存到了别处", v.rationale)


class DeserOracleTest(unittest.TestCase):
    def verdict(self, roles, **kw):
        o = ORACLE_REGISTRY["deserialization_marker_present"]()
        return o.run(roles, o.Args(**kw))

    def test_framework_error_is_hypothesis(self):
        v = self.verdict([obs("baseline", '{"ok":true}', 200, method="GET"),
                          obs("probe", "java.io.InvalidClassException: pta", 500)])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.80)
        self.assertEqual(verdict_status(v.confidence), "hypothesis")

    def test_generic_error_is_not_evidence(self):
        v = self.verdict([obs("baseline", '{"ok":true}', 200, method="GET"),
                          obs("probe", "internal error", 500)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.10)

    def test_baseline_already_errors(self):
        # 基线就报同样的错：错误不可归因于序列化流
        v = self.verdict([obs("baseline", "java.io.InvalidClassException: pta", 500, method="GET"),
                          obs("probe", "java.io.InvalidClassException: pta", 500)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.15)

    def test_denied(self):
        v = self.verdict([obs("baseline", "{}", 200, method="GET"),
                          obs("probe", "no", 403)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)


class PayloadTest(unittest.TestCase):
    def test_upload_payload_declares_its_own_content_type(self):
        cls = payloads.REGISTRY["upload_shell"]
        self.assertIn("multipart/form-data", cls.content_type)
        body = payloads.render("upload_shell", nonce_value="ab12cd34")
        self.assertIn('name="file"', body)
        self.assertIn("ptaab12cd34", body)
        self.assertIn(payloads.upload_file_name(), body)

    def test_xxe_payload_is_xml_with_entity(self):
        cls = payloads.REGISTRY["xxe_entity"]
        self.assertEqual(cls.content_type, "application/xml")
        body = payloads.render("xxe_entity", oob="http://oob.test/t/abc")
        self.assertIn("<!ENTITY xxe SYSTEM", body)
        self.assertIn("http://oob.test/t/abc", body)

    def test_deser_payload_keeps_magic_bytes(self):
        cls = payloads.REGISTRY["deser_java"]
        self.assertEqual(cls.encoding, "latin-1")
        raw = payloads.render("deser_java").encode(cls.encoding)
        # UTF-8 会把 0xAC 编成两字节，序列化流就废了
        self.assertEqual(raw[:4], b"\xac\xed\x00\x05")

    def test_new_templates_lint(self):
        for tid in ("upload-rce", "xxe-entity", "deserialization-marker"):
            raw = [t for t in vhx.TEMPLATES if t["id"] == tid][0]
            self.assertEqual(vhx.lint(raw), [], tid)
        up = [t for t in vhx.TEMPLATES if t["id"] == "upload-rce"][0]
        self.assertTrue(up["requires_approval"])
        self.assertEqual(up["side_effect_level"], "L2")


class UploadServer(Transport):
    """POST /api/upload 收文件；GET /uploads/<name> 取回。

    mode: vuln(当 html 返回) / plain(当 text/plain 返回) / no_store(201 但没落盘)
          / deny(403) / reject(415)
    """

    def __init__(self, mode="vuln"):
        self.mode = mode
        self.sent = []
        self.files = {}

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        t0 = time.perf_counter()
        path, method = req.raw_path.split("?", 1)[0], req.method.upper()
        status, ctype, body = 404, "text/plain", b"not found"
        if path == "/api/upload" and method == "POST":
            if self.mode == "deny":
                status, ctype, body = 403, "application/json", b'{"error":"forbidden"}'
            elif self.mode == "reject":
                status, ctype, body = 415, "application/json", b'{"error":"unsupported"}'
            else:
                status, ctype, body = 201, "application/json", b'{"ok":true}'
                if self.mode != "no_store":
                    self.files[payloads.upload_file_name()] = (req.body or b"", req.headers)
        elif path.startswith("/uploads/") and method == "GET":
            name = path.rsplit("/", 1)[-1]
            hit = self.files.get(name)
            if hit:
                status = 200
                ctype = "text/plain" if self.mode == "plain" else "text/html"
                body = hit[0]
        return RawResponse(status=status, reason="OK", http_version="HTTP/1.1",
                           headers=(("Content-Type", ctype),), body=body,
                           t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


class DeserServer(Transport):
    def __init__(self, mode="vuln"):
        self.mode = mode
        self.sent = []

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        t0 = time.perf_counter()
        body = req.body or b""
        if req.method.upper() == "POST" and body.startswith(b"\xac\xed\x00\x05"):
            if self.mode == "vuln":
                status, msg = 500, b'{"error":"java.io.InvalidClassException: pta; local class incompatible"}'
            elif self.mode == "reject":
                status, msg = 400, b'{"error":"bad request"}'
            else:
                status, msg = 500, b'{"error":"internal error"}'
        else:
            status, msg = 200, b'{"ok":true}'
        return RawResponse(status=status, reason="OK", http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),), body=msg,
                           t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


def _tpl(tid):
    return vhx.load([t for t in vhx.TEMPLATES if t["id"] == tid][0])


class ExecutorCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-upl-")
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("app.test",),
                                        allow_private=True, rate_per_host=200, max_requests=200))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def ws_with(self, transport, oob=None):
        return open_workspace(self.root, transport=transport, oob=oob,
                              dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))


class UploadExecutorTest(ExecutorCase):
    def run_case(self, mode="vuln", approve=True):
        srv = UploadServer(mode)
        ws = self.ws_with(srv)
        if approve:
            ws.gate.decide(ENG, "http_probe", "app.test", "body:file", "upload_shell", "L2",
                           "approve", scope="class")
        f = Executor(ws.probe, ws.store, ENG).run(
            _tpl("upload-rce"),
            Target(url="http://app.test/api/upload", method="POST", param_path="body:file",
                   identity_probe="none",
                   verify_url="http://app.test/uploads/%s" % payloads.upload_file_name()))
        return ws, srv, f

    def test_confirmed_through_readback(self):
        ws, srv, f = self.run_case()
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertAlmostEqual(f.confidence, 0.95)
        # 上传请求里必须带 multipart，不能被 JSON 分支吃掉
        posts = [r for r in srv.sent if r.method.upper() == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertIn("multipart/form-data", dict((k.lower(), v) for k, v in posts[0].headers)["content-type"])
        self.assertIn("pta", posts[0].body.decode("utf-8"))

    def test_plain_readback_keeps_rce_out_of_the_claim(self):
        # 能取回但返回 text/plain：落地成立、RCE 不成立，分数就该低一档
        ws, srv, f = self.run_case(mode="plain")
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertAlmostEqual(f.confidence, 0.88)
        self.assertIn("不成立", f.verdict["rationale"])

    def test_no_store_is_refuted(self):
        ws, srv, f = self.run_case(mode="no_store")
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertLessEqual(f.confidence, 0.15)

    def test_denied(self):
        ws, srv, f = self.run_case(mode="deny")
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertEqual(f.confidence, 0.0)

    def test_rejected_media_type(self):
        ws, srv, f = self.run_case(mode="reject")
        self.assertEqual(f.status, "refuted", f.verdict)

    def test_needs_approval_first(self):
        ws, srv, f = self.run_case(approve=False)
        self.assertTrue(f.stop_reason.startswith("pending_approval"), f.stop_reason)
        self.assertEqual([r for r in srv.sent if r.method.upper() == "POST"], [])


class XxeMock(MockTransport):
    """"解析器"只在 XML 里真的引用了实体时去取那个 URL。"""

    def __init__(self, routes, collector, parse=True):
        MockTransport.__init__(self, routes)
        self.collector = collector
        self.parse = parse

    def send(self, req, timeout_s=10.0):
        body = (req.body or b"").decode("latin-1")
        if self.parse and "<!ENTITY" in body:
            m = re.search(r'SYSTEM "([^"]+)"', body)
            if m:
                token = m.group(1).rstrip("/").rsplit("/", 1)[-1]
                self.collector.inject(token, protocol="http", source_ip="198.51.100.7")
        return MockTransport.send(self, req, timeout_s)


ROUTES = [MockRoute("POST", "app.test", "/api/import", 200,
                    (("Content-Type", "application/json"),), b'{"ok":true}')]


class XxeTest(ExecutorCase):
    def run_case(self, parse=True, approve=True):
        oob = OobCollector(public_host="127.0.0.1", bind_host="127.0.0.1").start()
        self.addCleanup(oob.stop)
        srv = XxeMock(ROUTES, oob, parse=parse)
        ws = self.ws_with(srv, oob=oob)
        if approve:
            ws.gate.decide(ENG, "http_probe", "app.test", "body:xml", "xxe_entity", "L2",
                           "approve", scope="class")
        f = Executor(ws.probe, ws.store, ENG).run(
            _tpl("xxe-entity"),
            Target(url="http://app.test/api/import", method="POST", param_path="body:xml",
                   oob_wait_s=1.0))
        return ws, srv, f

    def test_callback_confirms(self):
        ws, srv, f = self.run_case()
        self.assertEqual(f.status, "confirmed", f.verdict)
        kinds = [r["payload_class"] for r in ws.store.list_evidence(ENG)]
        self.assertIn("xxe_entity", kinds)
        # 实体 URL 必须带本次 arm 的 token，否则 wait() 永远等不到
        body = srv.sent[-1].body.decode("latin-1")
        self.assertRegex(body, r"/t/[0-9a-f]{8,}")

    def test_no_callback_is_not_evidence(self):
        ws, srv, f = self.run_case(parse=False)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertEqual(f.confidence, 0.0)

    def test_needs_approval(self):
        ws, srv, f = self.run_case(approve=False)
        self.assertTrue(f.stop_reason.startswith("pending_approval"), f.stop_reason)


class DeserExecutorTest(ExecutorCase):
    def test_framework_error_is_hypothesis(self):
        srv = DeserServer("vuln")
        ws = self.ws_with(srv)
        f = Executor(ws.probe, ws.store, ENG).run(
            _tpl("deserialization-marker"),
            Target(url="http://app.test/api/import", method="POST", param_path="body:data"))
        self.assertEqual(f.status, "hypothesis", f.verdict)
        self.assertAlmostEqual(f.confidence, 0.80)
        # 基线是同一个 POST 但空体（模板 baseline.required），只数带序列化流的那一发
        payloads_sent = [r for r in srv.sent if (r.body or b"").startswith(b"\xac\xed\x00\x05")]
        self.assertEqual(len(payloads_sent), 1)

    def test_generic_error_is_refuted(self):
        srv = DeserServer("generic")
        ws = self.ws_with(srv)
        f = Executor(ws.probe, ws.store, ENG).run(
            _tpl("deserialization-marker"),
            Target(url="http://app.test/api/import", method="POST", param_path="body:data"))
        self.assertEqual(f.status, "refuted", f.verdict)

    def test_endpoint_rejects_format(self):
        srv = DeserServer("reject")
        ws = self.ws_with(srv)
        f = Executor(ws.probe, ws.store, ENG).run(
            _tpl("deserialization-marker"),
            Target(url="http://app.test/api/import", method="POST", param_path="body:data"))
        self.assertEqual(f.status, "refuted", f.verdict)


if __name__ == "__main__":
    unittest.main()
