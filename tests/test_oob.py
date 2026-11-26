"""OOB 收集器 + 回连判定 + SSRF 闭环。"""
import socket
import struct
import threading
import unittest
import urllib.request

from pta import vhx
from pta.executor import Executor, Target
from pta.models import verdict_status
from pta.oob import OobCollector
from pta.oracles import OobCallbackReceived, Observation
from pta.transport import MockRoute, MockTransport
from support import WorkspaceCase


def dns_query(name: str, qtype: int = 1) -> bytes:
    tid = b"\x12\x34"
    header = tid + b"\x01\x00" + struct.pack(">HHHH", 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.oob = OobCollector(public_host="127.0.0.1", bind_host="127.0.0.1").start()
        self.addCleanup(self.oob.stop)

    def test_http_callback_recorded(self):
        token = self.oob.arm("idor", note="t")
        with urllib.request.urlopen(self.oob.url_for(token), timeout=5) as r:
            self.assertEqual(r.status, 200)
        calls = self.oob.check(token)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].protocol, "http")
        self.assertIn("127.0.0.1", calls[0].source_ip)
        self.assertFalse(calls[0].self_trigger)

    def test_unknown_token_ignored(self):
        token = self.oob.arm("x")
        with urllib.request.urlopen(
                "http://127.0.0.1:%d/t/deadbeefdeadbeef" % self.oob.http_port, timeout=5):
            pass
        self.assertEqual(self.oob.check("deadbeefdeadbeef"), [])
        self.assertEqual(len(self.oob.check(token)), 0)

    def test_dedup_counts(self):
        token = self.oob.arm("x")
        for _ in range(3):
            urllib.request.urlopen(self.oob.url_for(token), timeout=5).read()
        calls = self.oob.check(token)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].count, 3)

    def test_dns_callback(self):
        token = self.oob.arm("ssrf-dns")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(dns_query("%s.127.0.0.1" % token), ("127.0.0.1", self.oob.dns_port))
        data, _ = sock.recvfrom(512)
        sock.close()
        self.assertTrue(data.startswith(b"\x12\x34"))
        calls = self.oob.check(token)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].protocol, "dns")
        self.assertTrue(calls[0].path.startswith(token))

    def test_self_trigger_flagged(self):
        oob = OobCollector(public_host="127.0.0.1", bind_host="127.0.0.1",
                           our_egress_ips=("127.0.0.1",)).start()
        self.addCleanup(oob.stop)
        token = oob.arm("x")
        urllib.request.urlopen(oob.url_for(token), timeout=5).read()
        self.assertTrue(oob.check(token)[0].self_trigger)

    def test_wait_timeout(self):
        token = self.oob.arm("x")
        self.assertEqual(self.oob.wait(token, timeout=0.3), [])


def cb_obs(role="callback", protocol="http", source_ip="203.0.113.9", token="t1"):
    return Observation(role=role, evidence_id="e-" + token, identity=source_ip, method="OOB",
                       url="oob://%s/%s" % (protocol, token), status=200,
                       content_type="text/plain", body_sha256="0" * 64, body_len=2,
                       body=b"ok", source_ip=source_ip, protocol=protocol, token=token)


class OracleTest(unittest.TestCase):
    def run_oracle(self, obs, **kw):
        return OobCallbackReceived().run(obs, OobCallbackReceived.Args(**kw))

    def test_http_callback_confirms(self):
        v = self.run_oracle([cb_obs()])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.95)
        self.assertEqual(verdict_status(v.confidence), "confirmed")

    def test_dns_only_is_hypothesis(self):
        v = self.run_oracle([cb_obs(protocol="dns")])
        self.assertTrue(v.passed)
        self.assertEqual(verdict_status(v.confidence), "hypothesis")

    def test_require_http_rejects_dns_only(self):
        v = self.run_oracle([cb_obs(protocol="dns")], require_http=True)
        self.assertFalse(v.passed)

    def test_self_trigger_rejected(self):
        v = self.run_oracle([cb_obs(source_ip="10.0.0.5")], our_egress_ips=("10.0.0.5",))
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)

    def test_no_callback_missing_evidence(self):
        v = self.run_oracle([])
        self.assertFalse(v.passed)
        self.assertIn("callback:*", v.missing_evidence)

    def test_non_callback_roles_ignored(self):
        v = self.run_oracle([cb_obs(role="probe")])
        self.assertFalse(v.passed)


class SsrfMock(MockTransport):
    """目标收到请求后真的去"请求"回连地址——模拟 SSRF。"""

    def __init__(self, routes, collector):
        MockTransport.__init__(self, routes)
        self.collector = collector

    def send(self, req, timeout_s=10.0):
        for _, value in req.query:
            if "/t/" in value:
                token = value.split("/t/", 1)[1].split("/", 1)[0].split("&", 1)[0]
                self.collector.inject(token, protocol="http", source_ip="198.51.100.7")
        return MockTransport.send(self, req, timeout_s)


ROUTES = [MockRoute("GET", "app.test", "/api/fetch", 200, (("Content-Type", "text/plain"),), b"ok")]


class ExecutorOobTest(WorkspaceCase):
    def test_ssrf_confirmed_via_callback(self):
        oob = OobCollector(public_host="127.0.0.1", bind_host="127.0.0.1").start()
        self.addCleanup(oob.stop)
        ws = self.make_ws(ROUTES, transport=SsrfMock(ROUTES, oob), oob=oob)
        # L2 需要审批：先批一个 class 级
        ws.gate.decide("ENG-T", "http_probe", "app.test", "query:url", "oob_url", "L2",
                       "approve", scope="class", note="test")
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            vhx.load([t for t in vhx.TEMPLATES if t["id"] == "ssrf-outbound"][0]),
            Target(url="http://app.test/api/fetch?url=x", param_path="query:url",
                   identity_probe="none", oob_wait_s=1.0))
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.85)
        kinds = [r["payload_class"] for r in ws.store.list_evidence("ENG-T")]
        self.assertIn("oob_url", kinds)
        self.assertEqual(len(f.evidence_ids), 2)  # probe + callback

    def test_ssrf_blocked_without_approval(self):
        oob = OobCollector(public_host="127.0.0.1", bind_host="127.0.0.1").start()
        self.addCleanup(oob.stop)
        ws = self.make_ws(ROUTES, transport=SsrfMock(ROUTES, oob), oob=oob)
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            vhx.load([t for t in vhx.TEMPLATES if t["id"] == "ssrf-outbound"][0]),
            Target(url="http://app.test/api/fetch?url=x", param_path="query:url",
                   oob_wait_s=0.2))
        self.assertTrue(f.stop_reason.startswith("pending_approval"), f.stop_reason)
        # 等审批不是"判否"：状态必须自己说出来，否则面板上会显示成 0 分的 refuted
        self.assertEqual(f.status, "pending_approval")
        self.assertIn("等待人工审批", f.verdict["rationale"])

    def test_ssrf_without_collector_raises(self):
        from pta.errors import VhxInvalid
        ws = self.make_ws(ROUTES)
        with self.assertRaises(VhxInvalid):
            Executor(ws.probe, ws.store, "ENG-T").run(
                vhx.load([t for t in vhx.TEMPLATES if t["id"] == "ssrf-outbound"][0]),
                Target(url="http://app.test/api/fetch?url=x", param_path="query:url"))


class TemplateTest(unittest.TestCase):
    def test_ssrf_template_lints(self):
        raw = [t for t in vhx.TEMPLATES if t["id"] == "ssrf-outbound"][0]
        self.assertEqual(vhx.lint(raw), [])
        self.assertTrue(raw["requires_approval"])
        self.assertEqual(raw["side_effect_level"], "L2")


if __name__ == "__main__":
    unittest.main()
