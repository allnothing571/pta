# -*- coding: utf-8 -*-
"""decoy 负对照：判"两个身份读到同一份内容"之前，先证明响应真的和对象 id 有关。

三条结论：
1. 服务端按 id 查（不存在的对象 404）→ 相似度证据成立，照旧 confirmed；
2. 服务端不看 id（任何值都同一份）→ decoy 也拿到同一份，降 0.35，不许判越权；
3. 一次都没连上（端口错、站点没起）→ hypothesis，不许落成"已否定"。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta import vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import RawResponse, Transport, TransportError  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-DCY"
OBJECT = b'{"id": 7, "user_id": 3, "total": 99}'


def _resp(status, body):
    now = 0.0
    return RawResponse(status=status, reason="x", http_version="HTTP/1.1",
                       headers=(("Content-Type", "application/json"),), body=body,
                       t_send=now, t_first_byte=now, t_end=now)


class IdServer(Transport):
    """mode=id_aware：只有 id=7 存在；mode=id_blind：任何 id 都是同一份。"""

    name = "id"

    def __init__(self, mode="id_aware"):
        self.mode = mode
        self.sent = []

    def send(self, req, timeout_s=10.0):
        query = dict(req.query)
        oid = query.get("id", "")
        self.sent.append(oid)
        if self.mode == "id_blind":
            return _resp(200, OBJECT)
        return _resp(200, OBJECT) if oid == "7" else _resp(404, b'{"error": "not found"}')


class DeadServer(Transport):
    """连不上：端口没开、站点没起。"""

    name = "dead"

    def send(self, req, timeout_s=10.0):
        raise TransportError("[WinError 10061] 由于目标计算机积极拒绝，无法连接。")


class DecoyCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-decoy-")
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("app.test",),
                                        allow_private=True, rate_per_host=200,
                                        max_requests=200))
        self.addCleanup(shutil.rmtree, self.root, True)

    def ws(self, transport):
        ws = open_workspace(self.root, transport=transport,
                            dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/alice/authorization", "Bearer A")
        ws.vault.put("cred/bob/authorization", "Bearer B")
        return ws

    def run_tpl(self, transport, url="http://app.test/api/orders?id=7"):
        ws = self.ws(transport)
        ex = Executor(ws.probe, ws.store, ENG)
        return ex.run(vhx.load([t for t in vhx.TEMPLATES if t["id"] == "idor-object-ref"][0]),
                      Target(url=url, param_path="query:id",
                             identity_baseline="alice", identity_probe="bob")), transport


class DecoyTest(DecoyCase):
    def test_id_aware_endpoint_stays_confirmed(self):
        f, srv = self.run_tpl(IdServer("id_aware"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.92)
        self.assertEqual(f.verdict["metrics"]["decoy_status"], 404)
        # 三发：baseline(7) / decoy(999999999) / probe(7)
        self.assertEqual(srv.sent, ["7", "999999999", "7"])

    def test_id_blind_endpoint_is_downgraded(self):
        f, srv = self.run_tpl(IdServer("id_blind"))
        self.assertFalse(f.status == "confirmed", f.verdict)
        self.assertAlmostEqual(f.confidence, 0.35)
        self.assertIn("不存在的对象", f.verdict["rationale"])
        self.assertEqual(f.verdict["metrics"]["decoy_similarity"], 1.0)
        self.assertEqual(srv.sent, ["7", "999999999", "7"])

    def test_probe_reads_the_same_id_not_neighbour(self):
        """判越权要求两个身份读**同一个对象**；相邻 id 是另一类猜测，不能混进来。"""
        f, srv = self.run_tpl(IdServer("id_aware"))
        self.assertEqual(srv.sent[0], srv.sent[-1])


class UnreachableTest(DecoyCase):
    def test_connection_error_is_hypothesis_not_refuted(self):
        f, _ = self.run_tpl(DeadServer())
        self.assertEqual(f.status, "hypothesis", f.verdict)
        self.assertAlmostEqual(f.confidence, 0.50)
        self.assertEqual(f.stop_reason, "unreachable")
        self.assertIn("连不上", f.verdict["rationale"])

    def test_no_decoy_slot_means_no_extra_request(self):
        f, srv = self.run_tpl(IdServer("id_aware"), url="http://app.test/")
        self.assertNotIn("999999999", srv.sent)
        self.assertEqual(len(srv.sent), 2)


class DecoyUrlTest(unittest.TestCase):
    def test_replaces_first_object_slot(self):
        from pta.graph import decoy_url
        self.assertEqual(decoy_url("http://x/api/orders?id=7&expand=items"),
                         "http://x/api/orders?id=999999999&expand=items")
        self.assertEqual(decoy_url("http://x/api/users/7"), "http://x/api/users/999999999")
        self.assertIsNone(decoy_url("http://x/"))
        self.assertIsNone(decoy_url("http://x/api/users/alice"))


if __name__ == "__main__":
    unittest.main()
