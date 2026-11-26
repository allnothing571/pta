"""两条新模板：path-traversal-lfi / open-redirect，以及它们的 oracle。"""
import copy
import unittest
from urllib.parse import unquote_plus

from pta import vhx
from pta.executor import Executor, Target
from pta.models import RawResponse
from pta.oracles import (Observation, RedirectTargetMatch, FileSignatureMatch,
                         build_oracle)
from pta.transport import MockTransport, Transport
from support import WorkspaceCase

PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
NOT_FOUND = b"<!doctype html><html><body><h1>404 Not Found</h1></body></html>"
ECHO_ERROR = b"error: no such file '../../../../etc/passwd' - file not exist"
SPA = b'<!doctype html><html><body><div id="root"></div></body></html>'
LISTING = b"<!doctype html><html><head><title>Index of /</title></head><body>...</body></html>"


def obs(role, body, status=200, headers=None, url="http://app.test/dl?file=x"):
    return Observation(role=role, evidence_id="ev-" + role, identity="none", method="GET",
                       url=url, status=status, content_type="text/plain",
                       body_sha256="0" * 64, body_len=len(body), body=body,
                       headers=headers or {})


def tpl(tid):
    return vhx.load(copy.deepcopy([t for t in vhx.TEMPLATES if t["id"] == tid][0]))


class FuncTransport(Transport):
    """按请求内容决定响应的"服务器"，用于穿越/跳转这类需要看参数才响应的场景。"""

    name = "func"

    def __init__(self, fn):
        self.fn = fn
        self.sent = []

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        q = unquote_plus("&".join("%s=%s" % (k, v) for k, v in req.query))
        status, headers, body = self.fn(q)
        return RawResponse(status=status, reason="", http_version="HTTP/1.1",
                           headers=tuple(headers), body=body,
                           t_send=0.0, t_first_byte=0.0, t_end=0.0)


class RedirectOracleTest(unittest.TestCase):
    def run_oracle(self, body_obs, **args):
        return RedirectTargetMatch().run([body_obs], RedirectTargetMatch.Args(**args))

    def test_external_host_confirmed(self):
        v = self.run_oracle(obs("probe", b"", status=302,
                                headers={"location": "https://redirect.test/abc"}),
                            expected_host="redirect.test")
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.85)

    def test_subdomain_matches_when_suffix_allowed(self):
        v = self.run_oracle(obs("probe", b"", status=302,
                                headers={"location": "https://evil.redirect.test/x"}),
                            expected_host="redirect.test")
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.85, places=2)

    def test_wrong_host_refuted(self):
        v = self.run_oracle(obs("probe", b"", status=302,
                                headers={"location": "https://other.example/x"}),
                            expected_host="redirect.test")
        self.assertFalse(v.passed)

    def test_relative_location_refuted(self):
        v = self.run_oracle(obs("probe", b"", status=302, headers={"location": "/home"}),
                            expected_host="redirect.test")
        self.assertFalse(v.passed)
        self.assertIn("相对路径", v.rationale)

    def test_200_is_not_redirect(self):
        v = self.run_oracle(obs("probe", b"<p>hi</p>", status=200,
                                headers={"location": "https://redirect.test/x"}),
                            expected_host="redirect.test")
        self.assertFalse(v.passed)

    def test_missing_location_gives_missing_evidence(self):
        v = self.run_oracle(obs("probe", b"", status=302), expected_host="redirect.test")
        self.assertFalse(v.passed)
        self.assertIn("probe:location", v.missing_evidence)

    def test_no_probe_is_insufficient(self):
        v = RedirectTargetMatch().run([obs("baseline", b"")],
                                      RedirectTargetMatch.Args(expected_host="redirect.test"))
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)

    def test_cross_site_without_expected_host_is_low_confidence(self):
        v = RedirectTargetMatch().run(
            [obs("probe", b"", status=302, headers={"location": "https://evil.test/x"})],
            RedirectTargetMatch.Args())
        self.assertTrue(v.passed)
        self.assertLess(v.confidence, 0.85)      # 只够 hypothesis


class TraversalOracleTest(unittest.TestCase):
    def score(self, body, **args):
        return FileSignatureMatch().run([obs("probe", body)],
                                        FileSignatureMatch.Args(**args))

    def test_passwd_confirmed(self):
        v = self.score(PASSWD, min_confidence=0.85)
        self.assertTrue(v.passed)
        self.assertIn("passwd_file", v.metrics["hits"])

    def test_404_html_refuted(self):
        v = self.score(NOT_FOUND, min_confidence=0.85)
        self.assertFalse(v.passed)

    def test_spa_shell_refuted(self):
        v = self.score(SPA, min_confidence=0.85)
        self.assertFalse(v.passed)
        self.assertIn("spa_shell", v.metrics["neg"])

    def test_error_page_echo_refuted(self):
        v = self.score(ECHO_ERROR, min_confidence=0.85)
        self.assertFalse(v.passed)
        self.assertIn("error_path_echo", v.metrics["neg"])

    def test_dir_listing_confirmed(self):
        v = self.score(LISTING, min_confidence=0.85)
        self.assertTrue(v.passed)
        self.assertIn("dir_listing", v.metrics["hits"])


class TraversalExecutorTest(WorkspaceCase):
    def ws(self, fn):
        return self.make_ws([], domains=("app.test",), transport=FuncTransport(fn))

    def test_lfi_confirmed_end_to_end(self):
        def fn(query):
            return (200, [("Content-Type", "text/plain")], PASSWD) if "etc/passwd" in query \
                else (404, [("Content-Type", "text/html")], NOT_FOUND)

        ws = self.ws(fn)
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("path-traversal-lfi"),
            Target(url="http://app.test/dl?file=notes.txt", param_path="query:file"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertEqual(len(f.evidence_ids), 1)

    def test_lfi_refuted_on_404(self):
        ws = self.ws(lambda q: (404, [("Content-Type", "text/html")], NOT_FOUND))
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("path-traversal-lfi"),
            Target(url="http://app.test/dl?file=notes.txt", param_path="query:file"))
        self.assertEqual(f.status, "refuted", f.verdict)

    def test_open_redirect_confirmed_end_to_end(self):
        def fn(query):
            if "redirect.test" in query:
                return 302, [("Location", "https://redirect.test/x")], b""
            return 200, [("Content-Type", "text/html")], b"<p>ok</p>"

        ws = self.ws(fn)
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("open-redirect"),
            Target(url="http://app.test/login?next=/home", param_path="query:next"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.85)

    def test_open_redirect_refuted_when_same_site(self):
        ws = self.ws(lambda q: (302, [("Location", "/login?next=/home")], b""))
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("open-redirect"),
            Target(url="http://app.test/login?next=/home", param_path="query:next"))
        self.assertEqual(f.status, "refuted", f.verdict)


class TemplateMetaTest(unittest.TestCase):
    def test_both_templates_lint_clean_and_registered(self):
        for tid in ("path-traversal-lfi", "open-redirect"):
            t = tpl(tid)
            self.assertEqual(vhx.lint(t.raw), [], tid)
            self.assertEqual(t.raw["side_effect_level"], "L1")
            build_oracle(t.raw["oracle"]["name"], t.raw["oracle"]["args"])

    def test_payload_classes_registered(self):
        from pta import payloads
        for name in ("traversal_path", "traversal_path_win", "external_url"):
            self.assertIn(name, payloads.REGISTRY)

    def test_external_url_is_harness_owned_host(self):
        from pta import payloads
        out = payloads.render("external_url", nonce_value="abc123")
        self.assertTrue(out.startswith("https://redirect.test/"), out)


if __name__ == "__main__":
    unittest.main()
