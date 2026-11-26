"""接口发现：从首页走到"这一串命令可以跑了"。

三件事要有牙：
- 候选的 URL 必须带 query 值（evidence 的 raw_path 不含 query，`--param query:id`
  要改的是那个值，不带就等于改空气）；
- 每条候选说明自己要几个身份，缺身份写进 blockers，但命令照样给（占位符顶着）；
- 没出候选的端点必须解释原因，否则"没发现"和"漏了"看起来一样。
"""
from __future__ import annotations

import json
import os
import unittest

from pta import discover as disc
from pta.planner import Asset
from pta.transport import MockRoute, MockTransport

from support import WorkspaceCase

INDEX = b"""<!doctype html><html><body>
<a href="/search?q=widget">search</a>
<a href="/product?id=3">p3</a>
<a href="/status?verbose=1">status</a>
<a href="/health">health</a>
<a href="/api/orders?id=7">order</a>
</body></html>"""

HTML = (("Content-Type", "text/html; charset=utf-8"),)
JSON = (("Content-Type", "application/json"),)


def routes():
    """顺序有讲究：MockTransport 命中第一条 prefix 匹配，"/" 放最后。"""
    return [
        MockRoute("GET", "app.test", "/search", 200, JSON, b'{"total":1}'),
        MockRoute("GET", "app.test", "/product", 200, HTML, b"<html>p3</html>"),
        MockRoute("GET", "app.test", "/status", 200, HTML, b"<html>verbose</html>"),
        MockRoute("GET", "app.test", "/health", 200, HTML, b"<html>ok</html>"),
        MockRoute("GET", "app.test", "/api/orders", 200, JSON, b'{"id":7,"owner":"a"}'),
        MockRoute("GET", "app.test", "/", 200, HTML, INDEX),
    ]


class NeedsTest(unittest.TestCase):
    def test_idor_needs_two_identities(self):
        tpl = disc._templates()["idor-object-ref"]
        needs = disc._needs(tpl)
        self.assertTrue(needs.probe)
        self.assertEqual(needs.count, 2)

    def test_plain_template_needs_none(self):
        self.assertEqual(disc._needs({"probe": {"action": "mutate_list"}}).count, 0)

    def test_declared_precondition_counts(self):
        tpl = {"preconditions": [{"kind": "identity_available", "role": "baseline"}]}
        needs = disc._needs(tpl)
        self.assertTrue(needs.baseline)
        self.assertFalse(needs.probe)


class CommandTest(unittest.TestCase):
    def _s(self, **kw):
        base = dict(url="http://app.test/api/orders?id=7", template_id="idor-object-ref",
                    title="对象越权", param_path="query:id", method="GET",
                    priority=0.75, rationale="", needs=disc.Needs(True, True))
        base.update(kw)
        return disc.Suggestion(**base)

    def test_paths_and_url_are_quoted(self):
        cmd = self._s().command(r"D:\work\pta", ("alice", "bob"))
        self.assertIn('--root "D:\\work\\pta"', cmd)
        self.assertIn('--url "http://app.test/api/orders?id=7"', cmd)

    def test_identities_are_filled_in(self):
        cmd = self._s().command("R", ("alice", "bob"))
        self.assertIn("--identity-baseline alice", cmd)
        self.assertIn("--identity-probe bob", cmd)

    def test_placeholders_when_identities_missing(self):
        cmd = self._s().command("R", ())
        self.assertIn("IDENTITY_A", cmd)
        self.assertIn("IDENTITY_B", cmd)

    def test_write_method_and_body_param(self):
        cmd = self._s(template_id="idor-write-object", param_path="body:*",
                      method="PUT", needs=disc.Needs(True, True)).command("R", ("a", "b"))
        self.assertIn("--method PUT", cmd)
        self.assertIn("--param body:*", cmd)

    def test_no_param_means_no_param_flag(self):
        cmd = self._s(template_id="info-disclosure-artifact", param_path="",
                      needs=disc.Needs()).command("R", ())
        self.assertNotIn("--param", cmd)


class BlockersTest(unittest.TestCase):
    def test_none_identity_points_at_auth_add(self):
        out = disc._blockers(disc.Needs(True, True), ())
        self.assertEqual(len(out), 1)
        self.assertIn("pta auth add", out[0])

    def test_one_identity_says_how_many_are_missing(self):
        out = disc._blockers(disc.Needs(True, True), ("alice",))
        self.assertIn("只有 1 个", out[0])

    def test_enough_identities_means_no_blocker(self):
        self.assertEqual(disc._blockers(disc.Needs(True, True), ("a", "b")), [])

    def test_template_without_needs_never_blocks(self):
        self.assertEqual(disc._blockers(disc.Needs(), ()), [])


class GapTest(unittest.TestCase):
    def test_unknown_param_name(self):
        reason = disc._gap_reason(Asset(url="http://app.test/status", params=("verbose",)))
        self.assertIn("不命中规则", reason)
        self.assertIn("verbose", reason)

    def test_unknown_body_field(self):
        reason = disc._gap_reason(Asset(url="http://app.test/x", body_params=("zzz",)))
        self.assertIn("请求体字段", reason)

    def test_write_method_without_fields(self):
        reason = disc._gap_reason(Asset(url="http://app.test/x", method="POST"))
        self.assertIn("写方法", reason)

    def test_plain_get_is_not_a_gap(self):
        # 无参 GET 本来就有 info-disclosure-artifact 兜底候选，再说一遍只是重复
        self.assertIsNone(disc._gap_reason(Asset(url="http://app.test/health")))


class DiscoverTest(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.ws = self.make_ws(routes())

    def test_it_produces_suggestions_from_a_single_seed(self):
        report = disc.discover(self.ws, ["http://app.test/"])
        tpls = {s.template_id for s in report.suggestions}
        self.assertIn("idor-object-ref", tpls)
        self.assertIn("sqli-error-boolean", tpls)
        self.assertIn("info-disclosure-artifact", tpls)
        self.assertGreater(report.requests, 0)

    def test_candidate_url_carries_the_query_value(self):
        report = disc.discover(self.ws, ["http://app.test/"])
        idor = [s for s in report.suggestions if s.template_id == "idor-object-ref"]
        self.assertTrue(idor)
        self.assertTrue(any("?id=7" in s.url for s in idor), [s.url for s in idor])
        # 每个 idor 候选的 URL 都得带 query，否则 --param query:id 改的是空气
        for s in idor:
            self.assertIn("?", s.url, s.url)

    def test_endpoint_without_rules_is_explained(self):
        report = disc.discover(self.ws, ["http://app.test/"])
        urls = {g.url for g in report.gaps}
        self.assertTrue(any("/status" in u for u in urls), urls)
        reason = [g.reason for g in report.gaps if "/status" in g.url][0]
        self.assertIn("不命中规则", reason)

    def _drop_fixture_identities(self):
        """support.WorkspaceCase 预置了 A/B 两个身份，这里要测「一个都没有」的情形。"""
        for ref in list(self.ws.vault.refs("cred/")):
            self.ws.vault.delete(ref)

    def test_missing_identities_become_blockers(self):
        self._drop_fixture_identities()
        report = disc.discover(self.ws, ["http://app.test/"])
        idor = [s for s in report.suggestions if s.template_id == "idor-object-ref"][0]
        self.assertTrue(idor.blockers)
        self.assertIn("pta auth add", idor.blockers[0])

    def test_no_crawl_reads_what_is_already_there(self):
        disc.discover(self.ws, ["http://app.test/"])
        again = disc.discover(self.ws, [], crawl=False)
        self.assertEqual(again.requests, 0)
        self.assertTrue(again.suggestions)
        self.assertTrue(any(s.template_id == "idor-object-ref" for s in again.suggestions))

    def test_crawl_without_seed_is_an_error(self):
        with self.assertRaises(ValueError):
            disc.discover(self.ws, [])

    def test_identities_show_up_in_report(self):
        # 夹具自带 A/B；再搬两个，命令里应该用的是排在最前的那两个
        self.ws.vault.put("cred/alice/authorization", "Bearer A")
        self.ws.vault.put("cred/bob/authorization", "Bearer B")
        report = disc.discover(self.ws, ["http://app.test/"])
        self.assertIn("alice", report.identities)
        self.assertIn("bob", report.identities)
        idor = [s for s in report.suggestions if s.template_id == "idor-object-ref"][0]
        self.assertEqual(idor.blockers, [])
        self.assertIn("--identity-probe", idor.command("R", report.identities))


class RenderTest(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.ws = self.make_ws(routes())

    def test_render_has_a_copyable_command_block(self):
        report = disc.discover(self.ws, ["http://app.test/"])
        text = "\n".join(disc.render(report, r"C:\work\pta"))
        self.assertIn("复制就能跑", text)
        self.assertIn('--root "C:\\work\\pta"', text)
        self.assertIn("没出候选的端点", text)

    def test_json_counts_match(self):
        report = disc.discover(self.ws, ["http://app.test/"])
        data = report.to_json()
        self.assertEqual(data["counts"]["suggestions"], len(report.suggestions))
        self.assertEqual(data["counts"]["pages"], len(report.crawl.pages))
        self.assertEqual(data["counts"]["blocked"],
                         sum(1 for s in report.suggestions if s.blockers))

    def test_write_report_lands_on_disk(self):
        report = disc.discover(self.ws, ["http://app.test/"])
        path = disc.write_report(self.ws, report)
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as fh:
            data = json.loads(fh.read())
        self.assertIn("suggestions", data)


class SafeUrlTest(unittest.TestCase):
    def test_secret_value_is_blanked(self):
        url = disc._safe_url("http://app.test/api/x?token=abc123&id=7")
        self.assertIn("token=", url)
        self.assertNotIn("abc123", url)
        # 非凭证参数必须留真值：改了空值的命令测的就不是原来那个接口
        self.assertIn("id=7", url)

    def test_plain_query_survives(self):
        self.assertEqual(disc._safe_url("http://app.test/api/x?id=7&page=2"),
                         "http://app.test/api/x?id=7&page=2")

    def test_no_query_is_returned_as_is(self):
        self.assertEqual(disc._safe_url("http://app.test/api/x"),
                         "http://app.test/api/x")


class AssetsFromCallsTest(unittest.TestCase):
    def test_http_call_becomes_asset(self):
        got = disc._assets_from_calls([{
            "url": "http://app.test/api/orders?id=7", "method": "get",
            "query_names": ["id"], "status": 200, "mime": "application/json"}],
            identity="A")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].url, "http://app.test/api/orders?id=7")
        self.assertEqual(got[0].method, "GET")
        self.assertEqual(got[0].params, ("id",))
        self.assertEqual(got[0].identity, "A")

    def test_same_endpoint_accumulates_hits(self):
        calls = [{"url": "http://app.test/api/orders?id=%d" % i} for i in range(3)]
        got = disc._assets_from_calls(calls)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].hits, 3)

    def test_non_http_is_dropped(self):
        calls = [{"url": "data:text/html,x"}, {"url": "about:blank"},
                 {"url": "chrome-extension://abc/x"}]
        self.assertEqual(disc._assets_from_calls(calls), [])

    def test_body_fields_from_post(self):
        got = disc._assets_from_calls([{
            "url": "http://app.test/api/comments", "method": "POST",
            "body_fields": ["content", "parent"]}])
        self.assertEqual(got[0].body_params, ("content", "parent"))

    def test_valued_url_wins_over_the_blank_one(self):
        # 同一个接口页面先发 `?id=` 再发 `?id=7`：留着空值那条，
        # 候选命令改的就是空气，图上也没有对象槽可外推
        calls = [{"url": "http://app.test/api/orders?id=", "method": "GET",
                  "query_names": ["id"]},
                 {"url": "http://app.test/api/orders?id=7", "method": "GET",
                  "query_names": ["id"]}]
        got = disc._assets_from_calls(calls)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].url, "http://app.test/api/orders?id=7")

    def test_params_are_unioned_across_calls(self):
        # 两次调用参数不同（A 屏 tab、B 屏 sort）：取第一条会漏掉另一个参数名
        calls = [{"url": "http://app.test/api/orders?id=7&tab=info", "method": "GET",
                  "query_names": ["id", "tab"]},
                 {"url": "http://app.test/api/orders?id=7&sort=asc", "method": "GET",
                  "query_names": ["id", "sort"]}]
        got = disc._assets_from_calls(calls)
        self.assertEqual(got[0].params, ("id", "sort", "tab"))

    def test_body_fields_are_unioned_too(self):
        calls = [{"url": "http://app.test/api/comments", "method": "POST",
                  "body_fields": ["content"]},
                 {"url": "http://app.test/api/comments", "method": "POST",
                  "body_fields": ["parent"]}]
        got = disc._assets_from_calls(calls)
        self.assertEqual(got[0].body_params, ("content", "parent"))

    def test_last_non_zero_status_wins(self):
        calls = [{"url": "http://app.test/api/orders?id=7", "status": 0},
                 {"url": "http://app.test/api/orders?id=7", "status": 200}]
        self.assertEqual(disc._assets_from_calls(calls)[0].status, 200)


class _StubBrowser:
    def __init__(self, res, seen):
        self.res = res
        self.seen = seen

    def navigate(self, req):
        self.seen.append(req)
        return self.res


class HarvestAssetsTest(unittest.TestCase):
    """浏览器这一路只用替身：真 Chrome 在沙箱里起不来，但替身能钉住契约。"""

    def setUp(self):
        from pta import browser as browsemod
        from pta import workspace as wsmod
        from pta.browser import NavResult

        self.browsemod = browsemod
        self.wsmod = wsmod
        self.seen = []
        self.res = NavResult(
            status="ok", final_url="http://app.test/", evidence_id="ev1",
            harvest_calls=[
                {"url": "http://app.test/api/orders?id=7", "method": "GET",
                 "query_names": ["id"]},
                {"url": "http://app.test/api/orders?id=8", "method": "GET",
                 "query_names": ["id"]},
                {"url": "http://app.test/api/token?token=zzz", "method": "GET"}])
        self.attach_error = None
        self._orig = (wsmod.attach_browser, wsmod.close_browser)
        wsmod.attach_browser = self._attach
        wsmod.close_browser = self._close
        self.addCleanup(self._restore)

    def _attach(self, ws):
        if self.attach_error is not None:
            raise self.attach_error
        ws.browser = _StubBrowser(self.res, self.seen)

    def _close(self, ws):
        ws.browser = None

    def _restore(self):
        self.wsmod.attach_browser, self.wsmod.close_browser = self._orig

    def _ws(self):
        from types import SimpleNamespace
        return SimpleNamespace(browser=None)

    def test_harvest_calls_become_assets(self):
        assets, info = disc.harvest_assets(self._ws(), "http://app.test/",
                                           identity="A", settle=0.1)
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["calls"], 3)
        self.assertEqual(len(assets), 2)              # orders 合并成一条，token 一条
        orders = [a for a in assets if "orders" in a.url][0]
        self.assertEqual(orders.hits, 2)
        self.assertEqual(orders.identity, "A")
        self.assertEqual(self.seen[0].identity, "A")   # 身份要真的带进浏览器
        self.assertTrue(self.seen[0].harvest)

    def test_secret_in_harvested_url_is_blanked(self):
        assets, _ = disc.harvest_assets(self._ws(), "http://app.test/", settle=0.1)
        token = [a for a in assets if "token" in a.url][0]
        self.assertNotIn("zzz", token.url)

    def test_browser_failure_is_reported_not_raised(self):
        self.attach_error = RuntimeError("mojo 命名管道被拒")
        assets, info = disc.harvest_assets(self._ws(), "http://app.test/")
        self.assertEqual(assets, [])
        self.assertFalse(info["ok"])
        self.assertIn("mojo", info["reason"])

    def test_navigation_error_is_reported(self):
        self.res = self.browsemod.NavResult(status="error", reason="10054")
        assets, info = disc.harvest_assets(self._ws(), "http://app.test/")
        self.assertEqual(assets, [])
        self.assertFalse(info["ok"])
        self.assertIn("10054", info["reason"])


class MergeHarvestTest(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.ws = self.make_ws(routes())

    def test_harvested_url_carries_the_value(self):
        from pta.planner import PlannerState
        self.ws.store  # 让 evidence 落库的是 discover 自己
        disc.discover(self.ws, ["http://app.test/"])
        extra = [Asset(url="http://app.test/search?q=abc", method="GET",
                       params=("q",), hits=2)]
        state = PlannerState.collect(self.ws, max_assets=200, extra_assets=extra)
        urls = [a.url for a in state.assets]
        self.assertIn("http://app.test/search?q=abc", urls)
        # 同一接口只留一条，且留下的是带 query 值的那条
        same = [u for u in urls if u.split("?")[0] == "http://app.test/search"]
        self.assertEqual(len(same), 1, same)

    def test_extra_asset_is_added_when_never_seen(self):
        from pta.planner import PlannerState
        extra = [Asset(url="http://app.test/api/secret?id=9", method="GET",
                       params=("id",))]
        state = PlannerState.collect(self.ws, max_assets=200, extra_assets=extra)
        self.assertIn("http://app.test/api/secret?id=9", [a.url for a in state.assets])

    def test_evidence_and_harvest_merge_across_port_notation(self):
        # 证据表写 `http://app.test:80/search`，harvest 抓到 `http://app.test/search?q=abc`
        # ——同一个接口。不归一默认端口就会留成两条，一条没值、一条有值。
        from pta.planner import PlannerState
        disc.discover(self.ws, ["http://app.test/"])
        extra = [Asset(url="http://app.test/search?q=abc", method="GET",
                       params=("q",), hits=1)]
        state = PlannerState.collect(self.ws, max_assets=200, extra_assets=extra)
        hits = [a.hits for a in state.assets
                if a.url.split("?")[0].rstrip("/").endswith("/search")]
        self.assertEqual(len(hits), 1, hits)
        self.assertGreaterEqual(hits[0], 2)
        self.assertIn("?q=abc", [a.url for a in state.assets
                                 if a.url.split("?")[0].endswith("/search")][0])


class GraphInReportTest(WorkspaceCase):
    """资产图的摘要要进报告，图外推的候选要能被认出来（它们是弱一档的证据）。"""

    def setUp(self):
        super().setUp()
        self.ws = self.make_ws(routes())

    def test_graph_summary_lands_in_report(self):
        report = disc.discover(self.ws, ["http://app.test/"])
        self.assertIsNotNone(report.graph)
        self.assertEqual(report.graph["nodes"], 6)      # 首页 + 5 个链过去的端点
        data = report.to_json()
        self.assertEqual(data["counts"]["graph_edges"], report.graph["edges"])
        self.assertEqual(data["counts"]["graph_candidates"],
                         sum(1 for s in report.suggestions if s.source == "graph"))

    def test_rendered_when_graph_has_edges(self):
        from unittest import mock
        extra = [Asset(url="http://app.test/api/users/7", method="GET", hits=1,
                       status=200, identity="A"),
                 Asset(url="http://app.test/api/users/8", method="GET", hits=1,
                       status=200, identity="A")]
        with mock.patch.object(disc, "harvest_assets", return_value=(extra, {"ok": True})):
            report = disc.discover(self.ws, ["http://app.test/"], browser=True)
        self.assertGreaterEqual(report.graph["edges"], 1)
        text = "\n".join(disc.render(report, self.ws.root))
        self.assertIn("资产图：", text)
        self.assertIn("sibling_object", text)
        # 同模板换对象是一条真候选：8 号被页面自己调过，6/9 号没探过
        graph_cands = [s for s in report.suggestions if s.source == "graph"]
        self.assertTrue(graph_cands, [s.url for s in report.suggestions])
        self.assertIn("≈", text)

    def test_graph_slots_zero_means_no_reserved_graph_candidates(self):
        from unittest import mock
        extra = [Asset(url="http://app.test/api/users/7", method="GET", status=200,
                       identity="A"),
                 Asset(url="http://app.test/api/users/8", method="GET", status=200,
                       identity="A")]
        with mock.patch.object(disc, "harvest_assets", return_value=(extra, {"ok": True})):
            report = disc.discover(self.ws, ["http://app.test/"], browser=True,
                                   max_candidates=2, graph_slots=0)
        self.assertFalse([s for s in report.suggestions if s.source == "graph"])


class BrowserFailureTest(DiscoverTest):
    def test_discover_survives_and_says_why(self):
        from unittest import mock
        with mock.patch("pta.workspace.attach_browser",
                        side_effect=RuntimeError("起不来")):
            report = disc.discover(self.ws, ["http://app.test/"], browser=True)
        self.assertFalse(report.browser["ok"])
        self.assertIn("起不来", report.browser["reason"])
        # HTTP 那一路照常出候选：浏览器只是多一个来源，不是前置条件
        self.assertTrue(report.suggestions)
        text = "\n".join(disc.render(report, self.ws.root))
        self.assertIn("浏览器：", text)


class DiagnosticsTest(unittest.TestCase):
    """「它停了我知道为什么停」：诊断只从句柄上看得出来的东西里说。"""

    def _report(self, **kw):
        base = dict(seeds=("http://app.test:8080/box/",), crawl=None,
                    identities=("A",), requests=1,
                    graph={"nodes": 2, "edges": 0, "kinds": {}})
        base.update(kw)
        return disc.Report(**base)

    def test_browser_landed_on_login_says_so(self):
        rep = self._report(browser={"ok": True, "calls": 1, "assets": 1,
                                    "final_url": "http://app.test:8080/login"})
        lines = disc._diagnose(rep)
        self.assertTrue(any("没登进去" in l for l in lines))
        self.assertTrue(any("auth check" in l for l in lines))

    def test_no_login_talk_when_the_page_did_not_move(self):
        rep = self._report(browser={"ok": True, "calls": 12, "assets": 5,
                                    "final_url": "http://app.test:8080/box/"})
        self.assertEqual(disc._diagnose(rep), [])

    def test_seed_that_is_already_a_login_page_is_not_blamed_on_the_cookie(self):
        rep = self._report(seeds=("http://app.test:8080/login",),
                           browser={"ok": True, "calls": 1, "assets": 0,
                                    "final_url": "http://app.test:8080/login"})
        self.assertFalse(any("没登进去" in l for l in disc._diagnose(rep)))

    def test_zero_pages_lists_the_skip_reasons(self):
        crawl = disc.ReconReport(seeds=("http://app.test:8080/",), requests=2,
                                 skipped=[{"url": "http://app.test:8080/", "reason": "fetch_failed"},
                                          {"url": "http://app.test:8080/a", "reason": "fetch_failed"}])
        lines = disc._diagnose(self._report(crawl=crawl))
        self.assertTrue(any("一页都没成" in l and "fetch_failed ×2" in l for l in lines))

    def test_blocked_redirect_gives_a_seed_that_works(self):
        crawl = disc.ReconReport(
            seeds=("http://app.test:8080/",), requests=1, pages=[],
            blocked_redirects=[{"url": "http://app.test:8080/",
                                "target": "http://app.test/start",
                                "reason": "连接 app.test:80 失败"}])
        lines = disc._diagnose(self._report(crawl=crawl))
        hint = [l for l in lines if "--seed" in l]
        self.assertEqual(len(hint), 1)
        self.assertIn("http://app.test:8080/start", hint[0])   # 端口补回来了
        self.assertIn("80", hint[0])                           # 原因也留着

    def test_crawl_landed_on_login_is_reported_without_a_browser(self):
        from pta.recon import Page
        crawl = disc.ReconReport(seeds=("http://app.test:8080/box",), requests=1, pages=[
            Page(url="http://app.test:8080/box", status=200,
                 content_type="text/html", depth=0,
                 final_url="http://app.test:8080/login")])
        lines = disc._diagnose(self._report(crawl=crawl))
        self.assertTrue(any("没登进去" in l for l in lines))

    def test_render_puts_the_block_above_the_table(self):
        rep = self._report(browser={"ok": True, "calls": 1, "assets": 1,
                                    "final_url": "http://app.test:8080/login"})
        rep.diagnostics = disc._diagnose(rep)
        text = "\n".join(disc.render(rep, "."))
        self.assertIn("为什么停在这儿：", text)
        self.assertLess(text.index("为什么停在这儿："), text.index("没有产生任何候选"))

    def test_port_restore_only_fills_in_the_missing_one(self):
        f = disc._port_restore
        self.assertEqual(f("http://a.test:8080/x", "http://a.test/start"),
                         "http://a.test:8080/start")
        # 目标自己写了端口，是它的真实意图
        self.assertEqual(f("http://a.test:8080/x", "http://a.test:9000/start"),
                         "http://a.test:9000/start")
        # 换了主机就别自作主张
        self.assertEqual(f("http://a.test:8080/x", "http://b.test/start"),
                         "http://b.test/start")
        # 原地址本来就是默认端口，没什么可补的
        self.assertEqual(f("http://a.test/x", "http://a.test/start"),
                         "http://a.test/start")
        self.assertEqual(f("http://a.test:8080/x", "http://a.test/start?q=1"),
                         "http://a.test:8080/start?q=1")


if __name__ == "__main__":
    unittest.main()
