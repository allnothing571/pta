"""侦察层：从一个种子 URL 铺开资产表。

重点不是"爬得多"，而是：
- 越界链接（别的域名、deny_paths）一步都不发；
- 抓到的页面自己带 query 参数 → Planner 能立刻提出候选；
- JS 里的接口路径能抽出来，且不把 .png/.css 当接口。
"""
from __future__ import annotations

import unittest

from pta.planner import Planner, PlannerState
from pta.recon import Recon, Recon, _js_endpoints, _norm, write_report
from pta.transport import MockRoute, MockTransport

from support import WorkspaceCase

INDEX = b"""<!doctype html><html><head>
<link rel="stylesheet" href="/static/site.css">
<script src="/static/app.js"></script>
</head><body>
<a href="/search?q=widget">search</a>
<a href="/api/users?id=1">user 1</a>
<a href="/logout">logout</a>
<a href="https://evil.example.net/steal">off-site</a>
<a href="/static/logo.png">logo</a>
<form action="/api/search" method="get">
  <input name="q"><input name="page"><button name="go">go</button>
</form>
<script>var cfg = {api: "/api/v2/orders?limit=10", flags: "/api/flags"};</script>
</body></html>"""

APP_JS = b"""fetch("/api/v1/profile"); var u = "/api/v1/items?id="; // "/static/x.css"
var full = "http://app.test/api/v1/export"; """

SEARCH = b'{"total":1,"items":[{"id":1}]}'
USERS = b'{"id":1,"email":"a@example.com"}'
LOGOUT = b"bye"


def routes():
    """注意顺序：MockTransport 命中第一条 prefix 匹配，"/" 必须放最后。"""
    html = (("Content-Type", "text/html; charset=utf-8"),)
    js = (("Content-Type", "application/javascript"),)
    j = (("Content-Type", "application/json"),)
    return [
        MockRoute("GET", "app.test", "/static/app.js", 200, js, APP_JS),
        MockRoute("GET", "app.test", "/static/site.css", 200, (("Content-Type", "text/css"),), b".a{}"),
        MockRoute("GET", "app.test", "/search", 200, j, SEARCH),
        MockRoute("GET", "app.test", "/api/users", 200, j, USERS),
        MockRoute("GET", "app.test", "/logout", 200, html, LOGOUT),
        MockRoute("GET", "app.test", "/", 200, html, INDEX),
    ]


class ReconTest(WorkspaceCase):
    def crawl(self, **kw):
        tx = MockTransport(routes())
        ws = self.make_ws(routes(), transport=tx)
        r = Recon(ws, max_pages=kw.pop("max_pages", 10), max_depth=kw.pop("max_depth", 2),
                  **kw).run(["http://app.test/"])
        return ws, tx, r

    def test_links_forms_and_scripts(self):
        ws, tx, r = self.crawl()
        urls = r.urls()
        self.assertIn("http://app.test/", urls)
        self.assertIn("http://app.test/search?q=widget", urls)
        self.assertIn("http://app.test/api/users?id=1", urls)
        self.assertIn("http://app.test/static/app.js", urls)

    def test_scope_and_static_are_never_fetched(self):
        ws, tx, r = self.crawl()
        sent = [t.raw_path + ("?" + "&".join("%s=%s" % kv for kv in t.query) if t.query else "")
                for t in tx.sent]
        self.assertFalse([s for s in sent if "logout" in s], sent)
        self.assertFalse([s for s in sent if "logo.png" in s], sent)
        self.assertFalse([s for s in sent if "evil.example.net" in s], sent)
        reasons = {s["reason"] for s in r.skipped}
        self.assertTrue(any("deny_paths" in x for x in reasons), reasons)
        self.assertIn("static_asset", reasons)
        self.assertIn("cross_origin", reasons)

    def test_js_endpoints_are_extracted(self):
        ws, tx, r = self.crawl()
        eps = r.endpoints()
        self.assertIn("/api/v1/profile", eps)
        self.assertIn("/api/v1/items?id=", eps)
        self.assertIn("/api/v2/orders?limit=10", eps)   # 行内脚本
        self.assertIn("http://app.test/api/v1/export", eps)
        self.assertNotIn("/static/x.css", eps)

    def test_forms_and_params(self):
        ws, tx, r = self.crawl()
        page = [p for p in r.pages if p.url == "http://app.test/"][0]
        self.assertEqual(len(page.forms), 1)
        self.assertEqual(page.forms[0].action, "/api/search")
        self.assertEqual(page.forms[0].params, ("q", "page", "go"))
        self.assertIn("q", r.params())
        self.assertIn("page", r.params())

    def test_max_pages_is_hard_cap(self):
        ws, tx, r = self.crawl(max_pages=2)
        self.assertEqual(len(r.pages), 2)
        self.assertEqual(len(tx.sent), 2)

    def test_max_depth_zero_fetches_only_seed(self):
        ws, tx, r = self.crawl(max_depth=0)
        self.assertEqual(len(r.pages), 1)

    def test_budget_stops_the_crawl(self):
        tx = MockTransport(routes())
        ws = self.make_ws(routes(), transport=tx)
        ws.budget.max_requests = 2
        r = Recon(ws, max_pages=10).run(["http://app.test/"])
        self.assertLessEqual(len(r.pages), 2)
        self.assertTrue(any(s["reason"] == "budget_exhausted" for s in r.skipped))

    def test_each_page_becomes_evidence_and_feeds_planner(self):
        ws, tx, r = self.crawl()
        rows = ws.store.list_evidence("ENG-T", "recon")
        self.assertGreaterEqual(len(rows), 3)
        state = PlannerState.collect(ws)
        urls = " ".join(a.url for a in state.assets)
        self.assertIn("/search", urls)
        self.assertIn("/api/users", urls)
        plan = Planner(ws).plan()
        tpls = {c.template_id for c in plan.candidates}
        self.assertIn("sqli-error-boolean", tpls)      # q 参数
        self.assertIn("idor-object-ref", tpls)         # id 参数

    def test_report_is_written(self):
        ws, tx, r = self.crawl()
        path = write_report(ws, r)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("\"pages\"", text)
        self.assertIn("/api/v1/profile", text)


class HelperTest(unittest.TestCase):
    def test_norm_strips_fragment_and_keeps_query(self):
        self.assertEqual(_norm("/a?x=1#top", "http://app.test/root"),
                         "http://app.test/a?x=1")

    def test_norm_drops_non_http(self):
        self.assertEqual(_norm("javascript:alert(1)", "http://app.test/"), "")
        self.assertEqual(_norm("mailto:a@b.c", "http://app.test/"), "")

    def test_js_endpoint_filter(self):
        eps = _js_endpoints('x("/a.png"); y("/api/x"); z("//cdn/x.js"); w("/b.css")')
        self.assertEqual(eps, ["/api/x"])


if __name__ == "__main__":
    unittest.main()
