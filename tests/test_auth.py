# -*- coding: utf-8 -*-
"""身份凭证：cURL 解析、cookie 文件、掩码、凭证仓、以及"头真的进了请求"。"""
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

from pta import credentials  # noqa: E402
from pta.probe import ProbeRequest  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockTransport  # noqa: E402
from pta.vault import Vault  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"

BASH_CURL = """curl 'http://app.test/api/me' \\
  -H 'accept: application/json' \\
  -H 'authorization: Bearer abc.def.ghi' \\
  -H 'cookie: session=s%3A1; csrftoken=zz' \\
  -H 'sec-ch-ua: "Chromium";v="157"' \\
  -H 'sec-fetch-mode: cors' \\
  -H 'user-agent: Mozilla/5.0' \\
  -H 'x-csrf-token: zz' \\
  --compressed"""

CMD_CURL = ('curl "http://app.test/api/me" ^\n'
            '  -H "authorization: Bearer abc.def.ghi" ^\n'
            '  -H "x-api-key: k-1"')


class ParseCurlTest(unittest.TestCase):
    def test_keeps_only_identity_headers(self):
        got = credentials.parse_curl(BASH_CURL)
        names = {n.lower() for n, _ in got.headers}
        self.assertEqual(names, {"authorization", "cookie", "x-csrf-token"})
        self.assertEqual(got.url, "http://app.test/api/me")
        self.assertEqual(got.method, "GET")
        dropped = {d.lower() for d in got.dropped}
        self.assertIn("user-agent", dropped)
        self.assertIn("sec-ch-ua", dropped)
        self.assertIn("accept", dropped)

    def test_keep_all_keeps_everything(self):
        got = credentials.parse_curl(BASH_CURL, keep_all=True)
        names = {n.lower() for n, _ in got.headers}
        self.assertIn("user-agent", names)
        self.assertIn("sec-fetch-mode", names)

    def test_windows_continuation(self):
        got = credentials.parse_curl(CMD_CURL)
        names = {n.lower() for n, _ in got.headers}
        self.assertEqual(names, {"authorization", "x-api-key"})

    def test_cookie_flag_becomes_header(self):
        got = credentials.parse_curl("curl http://app.test/x -b 'a=1; b=2'")
        self.assertEqual(dict((k.lower(), v) for k, v in got.headers)["cookie"], "a=1; b=2")

    def test_explicit_drop_wins(self):
        got = credentials.parse_curl(BASH_CURL, drop_extra=("X-CSRF-Token",))
        names = {n.lower() for n, _ in got.headers}
        self.assertNotIn("x-csrf-token", names)
        self.assertIn("x-csrf-token", {d.lower() for d in got.dropped})

    def test_rejects_garbage(self):
        for text in ("", "   ", "curl http://app.test/x -H 'no-colon'"):
            with self.assertRaises(credentials.CredentialError):
                credentials.parse_curl(text)

    def test_rejects_non_http_url(self):
        with self.assertRaises(credentials.CredentialError):
            credentials.parse_curl("curl ftp://app.test/x")

    def test_missing_url(self):
        with self.assertRaises(credentials.CredentialError):
            credentials.parse_curl("curl -H 'authorization: x'")

    def test_post_method_inferred_from_data(self):
        got = credentials.parse_curl("curl http://app.test/x -d 'a=1'")
        self.assertEqual(got.method, "POST")


class CookieFileTest(unittest.TestCase):
    def test_netscape_seven_columns(self):
        text = ("# Netscape HTTP Cookie File\n"
                "app.test\tFALSE\t/\tFALSE\t0\tsession\ts%3A1\n"
                "app.test\tFALSE\t/\tFALSE\t0\tcsrftoken\tzz\n")
        self.assertEqual(credentials.parse_cookie_file(text), "session=s%3A1; csrftoken=zz")

    def test_key_value_lines(self):
        self.assertEqual(credentials.parse_cookie_file("a=1; b=2"), "a=1; b=2")

    def test_httponly_prefix_and_override(self):
        text = ("#HttpOnly_app.test\tFALSE\t/\tFALSE\t0\tsid\told\n"
                "app.test\tFALSE\t/\tFALSE\t0\tsid\tnew\n")
        self.assertEqual(credentials.parse_cookie_file(text), "sid=new")

    def test_empty(self):
        self.assertEqual(credentials.parse_cookie_file("# only comments\n\n"), "")


class HeaderHelperTest(unittest.TestCase):
    def test_merge_later_wins_case_insensitive(self):
        a = (("Cookie", "x=1"), ("X-A", "1"))
        b = (("cookie", "y=2"),)
        merged = dict((k.lower(), v) for k, v in credentials.merge_headers(a, b))
        self.assertEqual(merged["cookie"], "y=2")
        self.assertEqual(merged["x-a"], "1")

    def test_mask_hides_middle(self):
        self.assertEqual(credentials.mask("abc"), "***")
        out = credentials.mask("Bearer abcdefghijklmnop")
        self.assertTrue(out.startswith("Bearer"))
        self.assertIn("…", out)
        self.assertIn("23 字节", out)

    def test_identity_name(self):
        self.assertEqual(credentials.check_identity("alice_2"), "alice_2")
        for bad in ("", "a b", "a/b", "管理"):
            with self.assertRaises(credentials.CredentialError):
                credentials.check_identity(bad)

    def test_header_lines(self):
        got = credentials.parse_header_lines(["X-A: 1", "", "X-B: 2"])
        self.assertEqual(got, (("X-A", "1"), ("X-B", "2")))


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pta-vault-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "vault.json")

    def test_identities_items_delete(self):
        v = Vault(self.path)
        v.put("cred/alice/cookie", "a=1")
        v.put("cred/alice/authorization", "Bearer x")
        v.put("cred/bob/cookie", "b=2")
        self.assertEqual(v.identities(), ["alice", "bob"])
        self.assertEqual(sorted(v.items("cred/alice/")),
                         ["cred/alice/authorization", "cred/alice/cookie"])
        self.assertTrue(v.delete("cred/alice/cookie"))
        self.assertFalse(v.delete("cred/alice/cookie"))
        self.assertEqual(v.refs("cred/alice/"), ["cred/alice/authorization"])

    def test_persists_across_instances(self):
        Vault(self.path).put("cred/alice/cookie", "a=1")
        self.assertEqual(Vault(self.path).get("cred/alice/cookie"), "a=1")


class InjectionTest(unittest.TestCase):
    """vault 里的身份头要真的进请求——这是这套东西唯一有用的地方。"""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-auth-")
        self.addCleanup(shutil.rmtree, self.root, True)
        init_workspace(self.root, Scope(engagement_id="ENG-AU", domains=("app.test",),
                                        allow_private=True, rate_per_host=200,
                                        max_requests=50))
        self.transport = MockTransport([])
        self.ws = open_workspace(self.root, transport=self.transport,
                                 dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))

    def _headers(self, identity="alice", extra=()):
        res = self.ws.probe.run(ProbeRequest(
            action_id="t", url="http://app.test/api/me", identity=identity,
            label="t", level="L1", headers_extra=tuple(extra)))
        self.assertEqual(res.status, "ok", res.reason)
        return self.transport.sent[-1].headers

    def test_vault_headers_are_sent(self):
        self.ws.vault.put("cred/alice/cookie", "session=abc")
        self.ws.vault.put("cred/alice/x-csrf-token", "zz")
        hdrs = dict((k.lower(), v) for k, v in self._headers())
        self.assertEqual(hdrs["cookie"], "session=abc")
        self.assertEqual(hdrs["x-csrf-token"], "zz")

    def test_headers_extra_still_wins(self):
        self.ws.vault.put("cred/alice/cookie", "session=abc")
        hdrs = dict((k.lower(), v) for k, v in self._headers(extra=(("Cookie", "session=zzz"),)))
        self.assertEqual(hdrs["cookie"], "session=zzz")

    def test_no_identity_means_no_cred_headers(self):
        self.ws.vault.put("cred/alice/cookie", "session=abc")
        hdrs = dict((k.lower(), v) for k, v in self._headers(identity="none"))
        self.assertNotIn("cookie", hdrs)

    def test_host_cannot_be_overridden_from_vault(self):
        self.ws.vault.put("cred/alice/host", "evil.test")
        hdrs = dict((k.lower(), v) for k, v in self._headers())
        self.assertEqual(hdrs["host"], "app.test")


if __name__ == "__main__":
    unittest.main()
