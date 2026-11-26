import unittest

from pta.errors import ScopeViolation
from pta.scope import Scope, check_request


class ScopeTest(unittest.TestCase):
    def scope(self, **kw):
        base = dict(engagement_id="E", domains=("app.test", "*.corp.test"))
        base.update(kw)
        return Scope(**base)

    def test_exact_domain(self):
        s = self.scope()
        self.assertTrue(s.domain_allowed("app.test"))
        self.assertFalse(s.domain_allowed("app.test.evil.com"))
        self.assertFalse(s.domain_allowed("evil.com"))

    def test_wildcard_one_level(self):
        s = self.scope()
        self.assertTrue(s.domain_allowed("api.corp.test"))
        self.assertTrue(s.domain_allowed("a.b.corp.test"))
        self.assertFalse(s.domain_allowed("corp.test"))

    def test_idna_and_case(self):
        s = self.scope(domains=("app.test",))
        self.assertTrue(s.domain_allowed("APP.TEST"))

    def test_private_ip_rejected(self):
        s = self.scope()
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1"):
            self.assertFalse(s.ip_allowed(ip), ip)
        self.assertTrue(s.ip_allowed("93.184.216.34"))

    def test_private_allowed_only_when_opted_in(self):
        s = self.scope(allow_private=True)
        self.assertTrue(s.ip_allowed("127.0.0.1"))

    def test_deny_paths(self):
        s = self.scope()
        with self.assertRaises(ScopeViolation):
            check_request(s, "GET", "https://app.test/logout")
        with self.assertRaises(ScopeViolation):
            check_request(s, "GET", "https://app.test/account/close?x=1")

    def test_url_with_credentials_rejected(self):
        s = self.scope()
        with self.assertRaises(ScopeViolation):
            check_request(s, "GET", "https://user:pass@app.test/")

    def test_port_restricted(self):
        s = self.scope()
        with self.assertRaises(ScopeViolation):
            check_request(s, "GET", "https://app.test:8443/")

    def test_l3_disabled(self):
        s = self.scope()
        with self.assertRaises(ScopeViolation):
            check_request(s, "GET", "https://app.test/", level="L3")

    def test_expired(self):
        s = self.scope(expires_at="2020-01-01T00:00:00")
        with self.assertRaises(ScopeViolation):
            check_request(s, "GET", "https://app.test/")


if __name__ == "__main__":
    unittest.main()
