"""SSRF 打内网服务（ssrf-internal-service + internal_service_fingerprint）。

证据只有两段：baseline（不带载荷的同一请求）与 probe（参数换成内网地址）。
判定靠回显里的服务指纹，不靠回连——内网服务不会主动连我们。
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from urllib.parse import unquote_plus

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta import vhx  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.oracles import Observation, ORACLE_REGISTRY  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockTransport, RawResponse  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-S"

APP_PAGE = b"<html><body><h1>fetch</h1><a href='/home'>home</a></body></html>"
METADATA = (b"ami-id\nami-launch-index\nami-manifest-path\nhostname\ninstance-action\n"
            b"instance-id\ninstance-type\nlocal-hostname\nplacement/\nsecurity-credentials/\n")
DOCKER = json.dumps({"ApiVersion": "1.41", "MinAPIVersion": "1.12", "GitCommit": "v20.10.7"},
                    sort_keys=True).encode()
ETCD = json.dumps({"etcdserver": "3.5.10", "etcdcluster": "3.5.0"}, sort_keys=True).encode()


def obs(role, body, status=200, identity="none", method="GET"):
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    return Observation(role=role, evidence_id="ev-%s-%d" % (role, status), identity=identity,
                       method=method, url="http://app.test/fetch?url=x", status=status,
                       content_type="text/html",
                       body_sha256="%064x" % (abs(hash(raw)) % (1 << 256)),
                       body_len=len(raw), body=raw, headers={})


def verdict(roles, **args):
    o = ORACLE_REGISTRY["internal_service_fingerprint"]()
    return o.run(roles, o.Args(**args))


class OracleTest(unittest.TestCase):
    def test_metadata_fingerprint_confirms(self):
        v = verdict([obs("baseline", APP_PAGE), obs("probe", METADATA)])
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.90)
        self.assertEqual(v.metrics["service"], "aws_metadata")
        self.assertIn("instance-id", v.metrics["markers_found"])

    def test_docker_fingerprint_confirms(self):
        v = verdict([obs("baseline", APP_PAGE), obs("probe", DOCKER)])
        self.assertTrue(v.passed)
        self.assertEqual(v.metrics["service"], "docker_api")

    def test_echo_same_as_baseline_is_not_evidence(self):
        v = verdict([obs("baseline", APP_PAGE), obs("probe", APP_PAGE)])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.15)
        self.assertIn("逐字相同", v.rationale)

    def test_no_fingerprint_scores_low(self):
        v = verdict([obs("baseline", APP_PAGE), obs("probe", b"<html>ok</html>")])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.10)
        self.assertIn("probe:service_markers", v.missing_evidence)

    def test_baseline_already_has_service_is_rejected(self):
        v = verdict([obs("baseline", ETCD), obs("probe", ETCD)])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.15)

    def test_single_marker_is_only_hypothesis(self):
        v = verdict([obs("baseline", APP_PAGE), obs("probe", b'{"platform":"linux"}')])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.55)
        self.assertIn("probe:more_markers", v.missing_evidence)

    def test_denied(self):
        v = verdict([obs("baseline", APP_PAGE), obs("probe", b'{"error":"blocked"}', 403)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)

    def test_server_error_has_no_echo(self):
        v = verdict([obs("baseline", APP_PAGE), obs("probe", b"", 502)])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.05)

    def test_missing_baseline(self):
        v = verdict([obs("probe", METADATA)])
        self.assertFalse(v.passed)
        self.assertIn("baseline", v.missing_evidence)

    def test_custom_signatures(self):
        v = verdict([obs("baseline", APP_PAGE), obs("probe", b"<x>hello inner-svc</x>")],
                    signatures={"inner": ("inner-svc", "hello")})
        self.assertTrue(v.passed)
        self.assertEqual(v.metrics["service"], "inner")


class GatewayTransport(MockTransport):
    """像一个"抓取 URL"的接口：GET /fetch?url=… 由服务端去取。"""

    def __init__(self, mode="vuln"):
        super().__init__([])
        self.mode = mode
        self.fetches = 0

    def _fetch(self, url):
        self.fetches += 1
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
        if url:
            if self.mode == "deny":
                status, body = 403, b'{"error":"private address blocked"}'
            elif self.mode == "ignore":
                status, body = 200, APP_PAGE
            elif self.mode == "rewrite":
                status, body = 200, (b'<html>cluster_name=lucene_version='
                                     b'You Know, for Search</html>')
            elif self.mode == "single":
                status, body = 200, b'{"platform":"linux"}'
            else:
                status, body = self._fetch(url)
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "text/html"),), body=body,
                           t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


class ExecutorTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-ssrf-int-")
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("app.test",),
                                        allow_private=True, rate_per_host=200, max_requests=200))
        self.ws = open_workspace(self.root, transport=GatewayTransport("vuln"),
                                 dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_case(self, mode="vuln", approve=True):
        srv = self.ws.probe.transport
        srv.mode = mode
        srv.fetches = 0
        if approve:
            self.ws.gate.decide(ENG, "http_probe", "app.test", "query:url",
                                "internal_metadata_url", "L2", "approve", scope="class")
            self.ws.gate.decide(ENG, "http_probe", "app.test", "query:url",
                                "internal_docker_url", "L2", "approve", scope="class")
            self.ws.gate.decide(ENG, "http_probe", "app.test", "query:url",
                                "internal_etcd_url", "L2", "approve", scope="class")
        eng = Executor(self.ws.probe, self.ws.store, ENG)
        tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == "ssrf-internal-service"][0])
        target = Target(url="http://app.test/fetch", param_path="query:url",
                        identity_baseline="none", identity_probe="none")
        return eng.run(tpl, target)

    def test_confirmed_when_metadata_echoes(self):
        f = self.run_case()
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.90)
        self.assertEqual(f.verdict["metrics"]["service"], "aws_metadata")
        self.assertEqual(len(f.evidence_ids), 2)

    def test_param_ignored_is_refuted(self):
        f = self.run_case(mode="ignore")
        self.assertEqual(f.status, "refuted")
        self.assertLessEqual(f.confidence, 0.15)

    def test_blacklist_is_refuted(self):
        f = self.run_case(mode="deny")
        self.assertEqual(f.status, "refuted")
        self.assertEqual(f.confidence, 0.0)

    def test_unapproved_sends_nothing(self):
        f = self.run_case(approve=False)
        self.assertEqual(f.status, "pending_approval")
        self.assertEqual(self.ws.probe.transport.fetches, 0)

    def test_critic_keeps_confirmed(self):
        f = self.run_case()
        crit = Critic(self.ws).review_finding(f, apply=False)
        self.assertEqual(crit.status, "kept", crit.to_json())


class TemplateMetaTest(unittest.TestCase):
    def test_template_is_registered_and_lint_clean(self):
        raw = [t for t in vhx.TEMPLATES if t["id"] == "ssrf-internal-service"][0]
        self.assertEqual(vhx.lint(raw), [])
        self.assertEqual(raw["side_effect_level"], "L2")
        self.assertTrue(raw["requires_approval"])
        self.assertEqual(raw["oracle"]["name"], "internal_service_fingerprint")
        hints = [h["payload_class"] for h in raw["mutator_hints"]]
        self.assertIn("internal_metadata_url", hints)

    def test_payload_classes_registered(self):
        from pta import payloads
        for name in ("internal_metadata_url", "internal_docker_url", "internal_etcd_url"):
            self.assertIn(name, payloads.REGISTRY)
            self.assertEqual(payloads.level_floor(name), "L2")

    def test_oracle_registered(self):
        self.assertIn("internal_service_fingerprint", ORACLE_REGISTRY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
