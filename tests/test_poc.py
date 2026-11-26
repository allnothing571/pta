# -*- coding: utf-8 -*-
"""证据 → PoC：结论里挂着的那一发请求，能不能原样还原出来。

四条结论：
1. 挑对证据。一条 idor 结论挂 4 条证据，PoC 必须挑 probe 那条，
   挑成 baseline 就成了"打的是正常请求"；
2. 秘密值解引用。CanonicalRequest 里只存 vault 引用，PoC 要能直接跑，
   所以渲染时必须换成明文（并且不把 sha256 当成值印出来）；
3. 证据对不上就不出 PoC。CAS 被删/内容被改要报错，不能悄悄输出另一份；
4. 四种渲染都能跑：curl / powershell / raw / python。
"""
from __future__ import annotations

import json
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

from pta import poc as poc_mod, vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import RawResponse, Transport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-POC"
OBJECT = b'{"id": 7, "user_id": 3, "total": 99}'


def _resp(status, body, ctype="application/json"):
    now = 0.0
    return RawResponse(status=status, reason="x", http_version="HTTP/1.1",
                       headers=(("Content-Type", ctype),), body=body,
                       t_send=now, t_first_byte=now, t_end=now)


class IdServer(Transport):
    """只有 id=7 存在；别的 id 404（decoy 也 404，所以判越权成立）。"""

    name = "id"

    def __init__(self):
        self.sent = []

    def send(self, req, timeout_s=10.0):
        oid = dict(req.query).get("id", "")
        self.sent.append({"id": oid, "auth": _auth(req)})
        return _resp(200, OBJECT) if oid == "7" else _resp(404, b'{"error": "not found"}')


def _auth(req):
    for name, value in req.headers:
        if name.lower() == "authorization":
            return value
    return ""


class PocCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-poc-")
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("app.test",),
                                        allow_private=True, rate_per_host=200,
                                        max_requests=200))
        self.addCleanup(shutil.rmtree, self.root, True)

    def make(self):
        ws = open_workspace(self.root, transport=IdServer(),
                            dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/alice/authorization", "Bearer AAA")
        ws.vault.put("cred/bob/authorization", "Bearer BBB")
        ws.vault.put("cred/bob/cookie", "session=s3cr3t")
        tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == "idor-object-ref"][0])
        f = Executor(ws.probe, ws.store, ENG).run(
            tpl, Target(url="http://app.test/api/orders?id=7", param_path="query:id",
                        identity_baseline="alice", identity_probe="bob"))
        return ws, f


class PickTest(PocCase):
    def test_roles_are_persisted_and_probe_is_picked(self):
        ws, f = self.make()
        self.assertEqual(f.status, "confirmed", f.verdict)
        roles = f.verdict.get("roles") or {}
        self.assertIn("probe", roles.values(), roles)

        poc = poc_mod.load(ws, f.id)
        self.assertEqual(poc.role, "probe")
        self.assertEqual(roles[poc.evidence_id], "probe")

    def test_probe_is_the_bob_request_not_the_baseline(self):
        """baseline 是 alice，probe 是 bob；拿错就变成「用 alice 打 alice」。"""
        ws, f = self.make()
        poc = poc_mod.load(ws, f.id)
        auth = [v for k, v in poc.headers if k.lower() == "authorization"]
        self.assertEqual(auth, ["Bearer BBB"], poc.headers)

    def test_last_picks_the_newest_finding(self):
        ws, f = self.make()
        poc = poc_mod.load(ws, last=True)
        self.assertEqual(poc.finding_id, f.id)

    def test_legacy_finding_without_roles_falls_back_to_payload_class(self):
        """P2.4 之前落的结论没有角色表：按 payload_class / 身份差异退化，并标注出来。"""
        ws, f = self.make()
        legacy = {"id": f.id, "template_id": f.template_id, "title": f.title,
                  "status": f.status, "confidence": f.confidence,
                  "evidence_ids": list(f.evidence_ids),
                  "verdict": {"metrics": f.verdict.get("metrics"),
                              "rationale": f.verdict.get("rationale")}}
        eid, role = poc_mod.pick_evidence(ws, legacy)
        self.assertIn(eid, f.evidence_ids)
        self.assertTrue(role.endswith("?"), role)


class LoadTest(PocCase):
    def test_vault_ref_is_resolved_to_plaintext(self):
        ws, f = self.make()
        poc = poc_mod.load(ws, f.id)
        names = [k.lower() for k, _ in poc.headers]
        self.assertIn("cookie", names, poc.headers)
        self.assertIn("session=s3cr3t", [v for k, v in poc.headers if k.lower() == "cookie"])

    def test_url_keeps_query_value_and_drops_default_port(self):
        ws, f = self.make()
        poc = poc_mod.load(ws, f.id)
        self.assertEqual(poc.url, "http://app.test/api/orders?id=7")

    def test_missing_finding_is_an_error(self):
        ws, _ = self.make()
        with self.assertRaises(poc_mod.PocError):
            poc_mod.load(ws, "deadbeefdeadbeef")

    def test_requires_id_or_last(self):
        ws, _ = self.make()
        with self.assertRaises(poc_mod.PocError):
            poc_mod.load(ws)

    def test_tampered_evidence_is_refused(self):
        """CAS 里 body 被删：宁可报错，也不能拿另一份内容当 PoC。"""
        ws, f = self.make()
        poc = poc_mod.load(ws, f.id)
        row = ws.store.get_evidence_row(poc.evidence_id)
        os.remove(ws.cas.path_for(row["body_sha256"]))
        with self.assertRaises(poc_mod.PocError):
            poc_mod.load(ws, f.id)

    def test_explain_says_what_this_request_proves(self):
        ws, f = self.make()
        text = "\n".join(poc_mod.explain(poc_mod.load(ws, f.id)))
        self.assertIn("证据：", text)
        self.assertIn("角色 probe", text)
        self.assertIn("判定：", text)
        self.assertIn("响应：200", text)


class RenderTest(PocCase):
    def test_curl(self):
        ws, f = self.make()
        text = poc_mod.render(poc_mod.load(ws, f.id), "curl")
        self.assertIn("curl.exe -sS -i -X GET", text)
        self.assertIn("'http://app.test/api/orders?id=7'", text)
        self.assertIn("-H 'Authorization: Bearer BBB'", text)

    def test_powershell_escapes_quotes_by_doubling(self):
        poc = poc_mod.Poc(finding_id="x", template_id="t", title="t", status="confirmed",
                          confidence=1.0, rationale="", method="GET",
                          url="http://app.test/a", headers=[("X-Note", "it's ok")])
        text = poc_mod.render(poc, "powershell")
        self.assertIn("-H 'X-Note: it''s ok'", text)
        self.assertIn(" `\n", text)

    def test_raw(self):
        ws, f = self.make()
        text = poc_mod.render(poc_mod.load(ws, f.id), "raw")
        self.assertTrue(text.startswith("GET /api/orders?id=7 HTTP/1.1\r\n"), repr(text[:60]))
        self.assertIn("Host: app.test\r\n", text)

    def test_python(self):
        ws, f = self.make()
        text = poc_mod.render(poc_mod.load(ws, f.id), "python")
        self.assertIn("http.client.HTTPConnection", text)
        self.assertIn("'/api/orders?id=7'", text)

    def test_body_goes_to_file_when_binary(self):
        poc = poc_mod.Poc(finding_id="x", template_id="t", title="t", status="confirmed",
                          confidence=1.0, rationale="", method="POST",
                          url="http://app.test/upload", body=b"\xac\xed\x00\x05", body_kind="raw")
        self.assertTrue(poc.binary_body)
        text = poc_mod.render(poc, "curl", body_path="POC_BODY.bin")
        self.assertIn("--data-binary @POC_BODY.bin", text)

    def test_unknown_format_is_rejected(self):
        poc = poc_mod.Poc(finding_id="x", template_id="t", title="t", status="confirmed",
                          confidence=1.0, rationale="")
        with self.assertRaises(poc_mod.PocError):
            poc_mod.render(poc, "yaml")


class ShowCliTest(PocCase):
    def test_show_last_prints_poc(self):
        from pta import cli

        self.make()
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["show", "--root", self.root, "--last"])
        out = buf.getvalue()
        self.assertEqual(code, 0, out)
        self.assertIn("--- 复制下面这段去打 ---", out)
        self.assertIn("curl.exe", out)

    def test_show_json_is_machine_readable(self):
        from pta import cli

        self.make()
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["show", "--root", self.root, "--last", "--json"])
        self.assertEqual(code, 0, buf.getvalue())
        data = json.loads(buf.getvalue())
        self.assertTrue(data["ok"])
        self.assertEqual(data["role"], "probe")
        self.assertIn("curl.exe", data["poc"])

    def test_show_unknown_finding_exits_1_with_json(self):
        from pta import cli

        self.make()
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["show", "--root", self.root, "nope"])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(buf.getvalue())["ok"])


class WriteBodyTest(PocCase):
    """写接口那次 PoC 必须带**请求**体。

    这里钉的是一个真出过的错：起初把 evidence 的响应体当成了请求体塞进 PoC，
    于是 GET 的 curl 后面挂了一段 `--data-binary '{"id":7,...}'`，
    复制出去打的已经是另一个请求了。响应和请求长得很像（都是 JSON），
    只有写接口能一眼看出来——所以用 PUT 这条链路钉。
    """

    def make_write(self):
        from test_write_idor import ObjectServer

        ws = open_workspace(self.root, transport=ObjectServer("vuln"),
                            dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/A/authorization", "Bearer A")
        ws.vault.put("cred/B/authorization", "Bearer B")
        ws.gate.decide(ENG, "http_probe", "app.test", "body:*", "write_marker",
                       "L2", "approve", scope="class")
        tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == "idor-write-object"][0])
        f = Executor(ws.probe, ws.store, ENG).run(
            tpl, Target(url="http://app.test/api/items/3", method="PUT", param_path="body:*",
                        identity_baseline="B", identity_probe="A",
                        body_json={"name": "widget"}))
        return ws, f

    def test_body_is_the_request_not_the_response(self):
        ws, f = self.make_write()
        self.assertEqual(f.status, "confirmed", f.verdict)

        poc = poc_mod.load(ws, f.id)
        self.assertEqual(poc.role, "probe")
        self.assertEqual(poc.method, "PUT")

        payload = json.loads(poc.body.decode("utf-8"))
        self.assertIn("name", payload)
        # 响应体里有 owner，请求体里没有：混了就会在这里露出来。
        self.assertNotIn("owner", payload, payload)
        # probe 那发是 204 空响应，所以这里同时钉住另一半：
        # 响应体为空也不该让请求体变空或者反过来被填上响应内容。
        self.assertEqual(poc.response_len, 0)
        self.assertNotEqual(poc.body_kind, "none")

    def test_curl_carries_the_same_body(self):
        ws, f = self.make_write()
        poc = poc_mod.load(ws, f.id)
        text = poc_mod.render(poc, "curl")
        self.assertIn("--data-binary", text)
        self.assertIn(json.loads(poc.body.decode("utf-8"))["name"], text)
        self.assertNotIn("owner", text)


if __name__ == "__main__":
    unittest.main()
