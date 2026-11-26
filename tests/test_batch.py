"""批量读：判的是"能读多少个"，而且要先证明这些响应真的是各自的对象。"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from typing import Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)

from pta import graph, vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.models import RawResponse  # noqa: E402
from pta.oracles import BatchUnauthorizedRead, Observation, build_oracle  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import Transport  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-T"          # 必须与 WorkspaceCase 的 scope 一致，否则证据落不到同一账上
BATCH = 8              # 测试里扫 8 个相邻对象，够验证分层又不必打 20 发


def _obs(role: str, status: int, body: bytes, url: str = "http://app.test/api/orders?id=8",
         identity: str = "A", method: str = "GET", ctype: str = "application/json") -> Observation:
    return Observation(
        role=role, evidence_id="e-%s-%d-%s" % (role, status, body[:8].hex()),
        identity=identity, method=method, url=url, status=status,
        content_type=ctype, body_sha256=hashlib.sha256(body).hexdigest(),
        body_len=len(body), body=body,
    )


class SweepUrlTest(unittest.TestCase):
    def test_path_segment(self):
        self.assertEqual(graph.sweep_urls("http://a.test/api/users/7", 3),
                         ["http://a.test/api/users/8",
                          "http://a.test/api/users/9",
                          "http://a.test/api/users/10"])

    def test_query_value_keeps_other_params(self):
        got = graph.sweep_urls("http://a.test/api/orders?id=7&expand=items", 2)
        self.assertEqual(got, ["http://a.test/api/orders?id=8&expand=items",
                               "http://a.test/api/orders?id=9&expand=items"])

    def test_uuid_is_not_enumerable(self):
        # uuid 没有"相邻"，硬扫只会打出一片 404 噪声
        self.assertEqual(graph.sweep_urls("http://a.test/api/users/abc-123", 5), [])

    def test_no_object_slot(self):
        self.assertEqual(graph.sweep_urls("http://a.test/health", 5), [])

    def test_step(self):
        self.assertEqual(graph.sweep_urls("http://a.test/api/orders?id=7", 2, step=10),
                         ["http://a.test/api/orders?id=17",
                          "http://a.test/api/orders?id=27"])

    def test_zero_count(self):
        self.assertEqual(graph.sweep_urls("http://a.test/api/users/7", 0), [])


class OracleTest(unittest.TestCase):
    def setUp(self):
        self.args = BatchUnauthorizedRead.Args()

    def _run(self, obs):
        return BatchUnauthorizedRead().run(obs, self.args)

    def _base(self):
        return _obs("baseline", 200, b'{"id":7,"owner":"me","total":1}')

    def _rows(self, statuses: List[int], per_id: bool = True) -> List[Observation]:
        out = []
        for i, st in enumerate(statuses):
            ident = 8 + i
            body = (b'{"id":%d,"owner":"user%d","total":%d}' % (ident, ident, ident)
                    if per_id else b'{"id":0,"owner":"x","total":0}')
            role = "probe" if i == 0 else "sweep"
            out.append(_obs(role, st, body,
                            url="http://app.test/api/orders?id=%d" % ident))
        return out

    def test_all_readable_is_confirmed(self):
        v = self._run([self._base()] + self._rows([200] * 10))
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.90, places=2)
        self.assertEqual(v.metrics["readable"], 10)

    def test_most_readable(self):
        v = self._run([self._base()] + self._rows([200] * 6 + [403] * 4))
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.86, places=2)

    def test_few_readable_is_not_enough(self):
        v = self._run([self._base()] + self._rows([200] * 2 + [403] * 8))
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.65, places=2)
        self.assertIn("个别可读", v.rationale)

    def test_none_readable_means_authorization_works(self):
        v = self._run([self._base()] + self._rows([403] * 10))
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("对象级授权", v.rationale)

    def test_decoy_with_same_body_downgrades(self):
        rows = self._rows([200] * 10, per_id=False)
        decoy = _obs("decoy", 200, b'{"id":0,"owner":"x","total":0}',
                     url="http://app.test/api/orders?id=999999999")
        v = self._run([self._base()] + rows + [decoy])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.30, places=2)
        self.assertIn("响应与对象 id 无关", v.rationale)

    def test_identical_bodies_across_ids_downgrades(self):
        # 没有 decoy 证据，但几个不同 id 的响应一模一样：读到的不是各自的对象
        v = self._run([self._base()] + self._rows([200] * 5, per_id=False))
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.35, places=2)
        self.assertIn("不是各自的对象", v.rationale)

    def test_missing_baseline(self):
        v = self._run(self._rows([200] * 5))
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("baseline", v.rationale)

    def test_baseline_failed_means_test_invalid(self):
        v = self._run([_obs("baseline", 403, b"no")] + self._rows([200] * 5))
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("这次测试不成立", v.rationale)

    def test_registered(self):
        self.assertIsInstance(build_oracle("batch_unauthorized_read"),
                              BatchUnauthorizedRead)

    def test_template_lints(self):
        tpl = [t for t in vhx.TEMPLATES if t["id"] == "idor-batch-sweep"]
        self.assertEqual(len(tpl), 1)
        self.assertEqual(vhx.lint(tpl[0]), [])
        self.assertIn("batch_sweep", tpl[0]["probe"]["sequence"])


# ---------- 端到端 ----------
class SweepServer(Transport):
    """三种目标：全开 / 只认自己那条 / 根本不看 id。"""

    name = "sweep-mock"

    def __init__(self, mode: str = "open"):
        self.mode = mode
        self.sent: List[Dict[str, object]] = []

    def send(self, req, timeout_s: float = 10.0) -> RawResponse:
        hdrs = {k.lower(): v for k, v in req.headers}
        auth = hdrs.get("authorization", "")
        ident = int(dict(req.query).get("id") or 0)
        self.sent.append({"id": ident, "auth": auth})
        if not auth:
            return _resp(401, b'{"error": "unauthorized"}')
        if self.mode == "blind":
            return _resp(200, b'{"id":0,"owner":"x","total":0}')
        if self.mode == "scoped":
            if ident == 7:
                return _resp(200, b'{"id":7,"owner":"A","total":1}')
            return _resp(403, b'{"error": "forbidden"}')
        if ident >= 1000:
            return _resp(404, b'{"error": "not found"}')
        return _resp(200, b'{"id":%d,"owner":"user%d","total":%d}' % (ident, ident, ident))


def _resp(status: int, body: bytes) -> RawResponse:
    return RawResponse(status=status, reason="x", http_version="HTTP/1.1",
                       headers=(("Content-Type", "application/json"),),
                       body=body, t_send=0.0, t_first_byte=0.0, t_end=0.0)


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.dirs: List[str] = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def _ws(self, srv: SweepServer):
        from pta.workspace import init_workspace, open_workspace
        root = tempfile.mkdtemp(prefix="pta-batch-")
        self.dirs.append(root)
        init_workspace(root, Scope(engagement_id=ENG, domains=("app.test",),
                                   allow_private=True, rate_per_host=500,
                                   max_requests=200))
        ws = open_workspace(root, transport=srv,
                            dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
        return ws

    def _tpl(self):
        raw = [t for t in vhx.TEMPLATES if t["id"] == "idor-batch-sweep"][0]
        raw = json.loads(json.dumps(raw))
        raw["probe"]["batch"]["count"] = BATCH
        return vhx.load(raw)

    def _run(self, mode: str):
        srv = SweepServer(mode)
        ws = self._ws(srv)
        f = Executor(ws.probe, ws.store, ENG).run(
            self._tpl(),
            Target(url="http://app.test/api/orders?id=7",
                   identity_baseline="A", identity_probe="A"))
        return srv, f

    def test_open_endpoint_is_confirmed(self):
        srv, f = self._run("open")
        self.assertEqual(f.status, "confirmed")
        self.assertAlmostEqual(f.confidence, 0.90, places=2)
        self.assertEqual(f.verdict["metrics"]["readable"], BATCH)
        # 扫的是 8..15 这一串，最后一定还有一发 decoy 打 999999999
        self.assertIn(8, [s["id"] for s in srv.sent])
        self.assertIn(999999999, [s["id"] for s in srv.sent])

    def test_scoped_endpoint_is_refuted(self):
        srv, f = self._run("scoped")
        self.assertEqual(f.status, "refuted")
        self.assertEqual(f.confidence, 0.0)
        self.assertIn("对象级授权", f.verdict["rationale"])

    def test_id_blind_endpoint_is_downgraded(self):
        srv, f = self._run("blind")
        self.assertEqual(f.status, "refuted")
        self.assertAlmostEqual(f.confidence, 0.30, places=2)
        self.assertIn("响应与对象 id 无关", f.verdict["rationale"])


if __name__ == "__main__":
    unittest.main()
