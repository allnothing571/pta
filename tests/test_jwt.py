"""JWT 信任边界：jwtlab 伪造、jwt_acceptance_check 判定、模板端到端。"""
import base64
import copy
import json
import unittest

from pta import jwtlab, payloads, vhx
from pta.errors import PayloadRejected
from pta.executor import Executor, Target
from pta.oracles import JwtAcceptanceCheck, Observation, build_oracle
from pta.transport import MockRoute
from support import WorkspaceCase


def b64(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


GOOD = "Bearer %s.%s.%s" % (b64({"alg": "HS256", "typ": "JWT"}),
                            b64({"sub": "7", "role": "user", "exp": 4102444800}),
                            "c2lnbmF0dXJl")
BODY = b'{"id":7,"email":"alice@corp.test","role":"user","orders":3}'


def obs(role, body, status=200, headers=None):
    return Observation(role=role, evidence_id="ev-" + role, identity="A", method="GET",
                       url="http://app.test/api/me", status=status, content_type="application/json",
                       body_sha256="0" * 64, body_len=len(body), body=body,
                       headers=headers or {})


class ForgeTest(unittest.TestCase):
    def test_none_variant_changes_alg_and_drops_signature(self):
        out = jwtlab.forge(GOOD, "none")
        header_seg, payload_seg, sig = out.split(" ")[1].split(".")
        header = json.loads(base64.urlsafe_b64decode(header_seg + "==").decode())
        self.assertEqual(header["alg"], "none")
        self.assertEqual(sig, "")
        self.assertEqual(payload_seg, GOOD.split(".")[1])   # claims 不动

    def test_strip_variant_keeps_alg(self):
        out = jwtlab.forge(GOOD, "strip")
        header_seg, _, sig = out.split(" ")[1].split(".")
        header = json.loads(base64.urlsafe_b64decode(header_seg + "==").decode())
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(sig, "")

    def test_prefix_preserved(self):
        self.assertTrue(jwtlab.forge(GOOD, "none").startswith("Bearer "))

    def test_unknown_variant_rejected(self):
        with self.assertRaises(PayloadRejected):
            jwtlab.forge(GOOD, "crack")

    def test_non_jwt_rejected(self):
        with self.assertRaises(PayloadRejected):
            jwtlab.forge("Bearer opaque-token", "none")
        self.assertFalse(jwtlab.is_jwt("opaque"))
        self.assertTrue(jwtlab.is_jwt(GOOD))

    def test_describe_hides_claim_values(self):
        info = jwtlab.describe(GOOD)
        self.assertEqual(info["alg"], "HS256")
        self.assertIn("role", info["claim_keys"])
        self.assertNotIn("alice", json.dumps(info))

    def test_payload_class_never_renders_literal(self):
        self.assertIn("jwt_forged", payloads.REGISTRY)
        with self.assertRaises(PayloadRejected):
            payloads.render("jwt_forged")


class JwtOracleTest(unittest.TestCase):
    def run_oracle(self, observations, **args):
        return JwtAcceptanceCheck().run(observations, JwtAcceptanceCheck.Args(**args))

    def test_equivalent_body_confirmed(self):
        v = self.run_oracle([obs("baseline", BODY), obs("probe", BODY)])
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.85)
        self.assertAlmostEqual(v.metrics["similarity"], 1.0, places=2)

    def test_401_refuted(self):
        v = self.run_oracle([obs("baseline", BODY), obs("probe", b"", status=401)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)

    def test_different_body_refuted(self):
        v = self.run_oracle([obs("baseline", BODY),
                             obs("probe", b"<html>login</html>")])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.5)

    def test_no_baseline_is_hypothesis_only(self):
        v = self.run_oracle([obs("probe", BODY)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.60, places=2)
        self.assertIn("baseline", v.missing_evidence)

    def test_missing_probe(self):
        v = self.run_oracle([obs("baseline", BODY)])
        self.assertFalse(v.passed)
        self.assertIn("probe", v.missing_evidence)

    def test_partial_similarity_is_hypothesis(self):
        # 词汇几乎一致但长度差一倍：相似度落在 0.5~0.9 之间，只够 hypothesis
        v = self.run_oracle([obs("baseline", BODY), obs("probe", BODY * 2)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.60, places=2)
        self.assertGreater(v.metrics["similarity"], 0.5)
        self.assertLess(v.metrics["similarity"], 0.9)


class JwtExecutorTest(WorkspaceCase):
    def make(self, forged_status, forged_body=BODY):
        forged = jwtlab.forge(GOOD, "none")
        routes = [
            MockRoute("GET", "app.test", "/api/me", 200,
                      (("Content-Type", "application/json"),), BODY, identity=GOOD),
            MockRoute("GET", "app.test", "/api/me", forged_status,
                      (("Content-Type", "application/json"),), forged_body, identity=forged),
        ]
        ws = self.make_ws(routes, domains=("app.test",))
        ws.vault.put("cred/A/authorization", GOOD)
        return ws

    def run_tpl(self, ws):
        tpl = vhx.load(copy.deepcopy(
            [t for t in vhx.TEMPLATES if t["id"] == "jwt-trust-boundary"][0]))
        return Executor(ws.probe, ws.store, "ENG-T").run(
            tpl, Target(url="http://app.test/api/me",
                        identity_baseline="A", identity_probe="A",
                        param_path="header:authorization"))

    def test_accepted_forgery_confirmed(self):
        ws = self.make(200)
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.85)
        self.assertEqual(len(f.evidence_ids), 2)

    def test_rejected_forgery_refuted(self):
        ws = self.make(401, b"")
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)

    def test_skips_when_credential_is_not_jwt(self):
        ws = self.make_ws([], domains=("app.test",))
        ws.vault.put("cred/A/authorization", "Bearer opaque")
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertIn("jwt_forged", json.dumps(f.verdict.get("skipped", [])))

    def test_template_meta(self):
        tpl = vhx.load(copy.deepcopy(
            [t for t in vhx.TEMPLATES if t["id"] == "jwt-trust-boundary"][0]))
        self.assertEqual(vhx.lint(tpl.raw), [])
        self.assertEqual(tpl.raw["side_effect_level"], "L1")
        build_oracle(tpl.raw["oracle"]["name"], tpl.raw["oracle"]["args"])


if __name__ == "__main__":
    unittest.main()
