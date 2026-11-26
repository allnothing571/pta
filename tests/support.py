"""测试脚手架：离线工作区 + 假 DNS + 固定响应。"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from typing import Sequence

from pta.scope import DnsPin, Scope
from pta.transport import MockRoute, MockTransport
from pta.workspace import init_workspace, open_workspace

PUBLIC_IP = "93.184.216.34"


def fake_dns(ips: Sequence[str] = (PUBLIC_IP,)) -> DnsPin:
    return DnsPin(resolver=lambda host: list(ips))


class WorkspaceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="pta-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def make_ws(self, routes, domains=("app.test",), allow_private=True, proxy=None,
                oob=None, transport=None):
        scope = Scope(
            engagement_id="ENG-T",
            domains=tuple(domains),
            allow_private=allow_private,
            rate_per_host=1000.0,
            max_requests=5000,
            egress_proxy=proxy,
        )
        init_workspace(self.tmp, scope)
        tx = transport if transport is not None else MockTransport(routes)
        ws = open_workspace(self.tmp, transport=tx, dns=fake_dns(), oob=oob)
        ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
        ws.vault.put("cred/B/authorization", "Bearer TOKEN-B")
        return ws


OBJECT_BODY = b'{"id":1,"email":"alice@example.com","phone":"13800000000","role":"user"}'


def idor_routes():
    return [
        MockRoute("GET", "app.test", "/api/users/1", 200, (("Content-Type", "application/json"),),
                  OBJECT_BODY, identity="Bearer TOKEN-A"),
        MockRoute("GET", "app.test", "/api/users/1", 200, (("Content-Type", "application/json"),),
                  OBJECT_BODY, identity="Bearer TOKEN-B"),
        MockRoute("GET", "app.test", "/api/users/2", 200, (("Content-Type", "application/json"),),
                  b'{"id":2,"email":"bob@example.com"}', identity="Bearer TOKEN-A"),
        MockRoute("GET", "app.test", "/api/users/2", 403, (("Content-Type", "application/json"),),
                  b'{"error":"forbidden"}', identity="Bearer TOKEN-B"),
    ]
