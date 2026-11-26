"""接口采集（harvest）测试：纯逻辑 + 协议级假 CDP。

分两层：
- `HarvesterUnitTest` 不碰网络，只喂 CDP 事件字典，钉住"同源过滤、类型过滤、
  按形状去重、参数名提取"这四条规则。
- `BrowserHarvestTest` 走真 WebSocket + 假 CDP，验证 `BrowserTool.navigate(harvest=True)`
  真的把页面自己发的调用落成了 `label=harvest` 的证据，且 query 值不入库。
"""
from __future__ import annotations

import json
import unittest

from pta import cdp
from pta.browser import BrowserTool, NavRequest
from pta.harvest import Call, Harvester, decode_body

from fake_cdp import FakeCdpServer, FakePage
from support import WorkspaceCase, fake_dns


def _req(rid, url, method="GET", rtype="XHR", post="", status=200, mime="application/json"):
    return [
        ("Network.requestWillBeSent", {"requestId": rid, "type": rtype,
                                       "request": {"url": url, "method": method,
                                                   **({"postData": post} if post else {})}}),
        ("Network.responseReceived", {"requestId": rid,
                                      "response": {"status": status, "mimeType": mime}}),
        ("Network.loadingFinished", {"requestId": rid}),
    ]


def _feed(h, events):
    for method, params in events:
        h.on_event(method, params)


class HarvesterUnitTest(unittest.TestCase):
    def harvester(self, hosts=("app.test",), limit=24):
        return Harvester(allowed_hosts=hosts, limit=limit)

    def test_shape_of_call(self):
        c = Call(request_id="1", method="post", url="http://app.test/api/v2/profile?a=1&b=2",
                 post_data='{"displayName": "w", "role": "user"}')
        self.assertEqual(c.parts(), ("http", "app.test", 80, "/api/v2/profile"))
        self.assertEqual(c.query_names(), ("a", "b"))
        self.assertEqual(c.body_fields(), ("displayName", "role"))
        self.assertEqual(c.shape(), ("POST", "/api/v2/profile", ("a", "b"),
                                     ("displayName", "role")))

    def test_form_body_fields(self):
        c = Call(request_id="1", method="POST", url="http://app.test/login",
                 post_data="user=w&pass=x&remember=1")
        self.assertEqual(c.body_fields(), ("pass", "remember", "user"))

    def test_garbage_body_has_no_fields(self):
        c = Call(request_id="1", method="POST", url="http://app.test/x", post_data="{oops")
        self.assertEqual(c.body_fields(), ())

    def test_cross_origin_is_dropped(self):
        h = self.harvester()
        _feed(h, _req("1", "https://cdn.other.test/lib.js"))
        _feed(h, _req("2", "http://app.test/api/items"))
        self.assertEqual([c.url for c in h.calls()], ["http://app.test/api/items"])
        self.assertEqual(h.stats()["skipped_cross_origin"], 1)

    def test_static_types_are_dropped(self):
        h = self.harvester()
        _feed(h, _req("1", "http://app.test/logo.png", rtype="Image"))
        _feed(h, _req("2", "http://app.test/style.css", rtype="Stylesheet"))
        _feed(h, _req("3", "http://app.test/api/items"))
        self.assertEqual([c.resource_type for c in h.calls()], ["XHR"])
        self.assertEqual(h.stats()["skipped_type"], 2)

    def test_same_shape_is_deduped_by_name_not_value(self):
        h = self.harvester()
        _feed(h, _req("1", "http://app.test/api/items?page=1&size=20"))
        _feed(h, _req("2", "http://app.test/api/items?page=2&size=20"))
        _feed(h, _req("3", "http://app.test/api/items?q=boots"))
        calls = h.calls()
        self.assertEqual(len(calls), 2, [c.url for c in calls])
        self.assertEqual(calls[0].url, "http://app.test/api/items?page=1&size=20")
        self.assertEqual(calls[1].query_names(), ("q",))

    def test_limit_truncates(self):
        h = self.harvester(limit=2)
        for i in range(5):
            _feed(h, _req(str(i), "http://app.test/api/r%d" % i))
        self.assertEqual(len(h.calls()), 2)

    def test_body_requests_skip_unfinished_and_failed(self):
        h = self.harvester()
        h.on_event("Network.requestWillBeSent", {
            "requestId": "1", "type": "XHR",
            "request": {"url": "http://app.test/api/a", "method": "GET"}})
        h.on_event("Network.loadingFinished", {"requestId": "1"})
        h.on_event("Network.requestWillBeSent", {
            "requestId": "2", "type": "XHR",
            "request": {"url": "http://app.test/api/b", "method": "GET"}})
        h.on_event("Network.loadingFailed", {"requestId": "2", "errorText": "aborted"})
        want = h.body_requests(h.calls())
        self.assertEqual([c.request_id for c in want], ["1"])

    def test_decode_body_handles_base64_and_plain(self):
        self.assertEqual(decode_body({"body": "hi", "base64Encoded": False}), b"hi")
        self.assertEqual(decode_body({"body": "aGk=", "base64Encoded": True}), b"hi")
        self.assertIsNone(decode_body({}))

    def test_data_urls_ignored(self):
        h = self.harvester()
        _feed(h, _req("1", "data:text/html,<p>x</p>"))
        self.assertEqual(h.calls(), [])


def _harvest_setup(self) -> None:
    WorkspaceCase.setUp(self)
    self.ws = self.make_ws([])
    self.page = FakePage(mode="vuln")
    self.page.api_calls = [
        {"url": "/api/v2/profile?tab=main", "method": "POST",
         "postData": '{"displayName": "w", "role": "user"}',
         "body": '{"displayName": "w", "role": "admin", "id": 7}'},
        {"url": "/api/v2/profile?tab=main", "method": "POST",
         "postData": '{"displayName": "x", "role": "user"}',
         "body": '{"displayName": "x", "role": "admin", "id": 7}'},
        {"url": "http://evil.test/beacon?u=1", "type": "Fetch", "body": "{}"},
        {"url": "/static/logo.png", "type": "Image"},
    ]
    self.server = FakeCdpServer(self.page).start()
    self.addCleanup(self.server.close)
    self.wsock = cdp.WebSocket("127.0.0.1", self.server.port, self.server.path, timeout=10)
    self.addCleanup(self.wsock.close)
    self.session = cdp.CdpSession(self.wsock)
    self.tool = BrowserTool(
        scope=self.ws.scope, store=self.ws.store, cas=self.ws.cas, budget=self.ws.budget,
        page_session=self.session, page_id="S1", target_id="T1",
        product="FakeCdp/1.0", dns=fake_dns(), bus=self.ws.bus,
    )


def _harvest_nav(self, **kw):
    return self.tool.navigate(NavRequest(url="http://app.test/search?q=hello",
                                         label="run/xss/test", settle_s=0.3, **kw))


class BrowserHarvestTest(WorkspaceCase):
    setUp = _harvest_setup
    nav = _harvest_nav

    def test_harvest_off_by_default(self):
        r = self.nav()
        self.assertEqual(r.status, "ok", r.reason)
        self.assertEqual(r.harvested, [])
        self.assertNotIn("Network.enable", self.server.methods)

    def test_harvest_records_calls_as_evidence(self):
        r = self.nav(harvest=True)
        self.assertEqual(r.status, "ok", r.reason)
        self.assertIn("Network.enable", self.server.methods)
        # 主文档一条 + 两个同形状 POST 合成一条；跨站与图片被丢
        self.assertEqual(len(r.harvested), 2, r.harvest_calls)
        call = [c for c in r.harvest_calls if c["resource_type"] == "XHR"][0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["path"], "/api/v2/profile")
        self.assertEqual(call["query_names"], ["tab"])
        self.assertEqual(call["body_fields"], ["displayName", "role"])

        row = self.ws.store.get_evidence_row(call["evidence_id"])
        self.assertIsNotNone(row)
        self.assertEqual(row["label"], "harvest")
        self.assertEqual(row["content_type"], "application/json")
        self.assertGreater(row["body_len"], 0)
        blob = self.ws.cas.get(row["body_sha256"])
        self.assertIn(b'"role": "admin"', blob)

    def test_query_values_are_not_persisted(self):
        r = self.nav(harvest=True)
        call = [c for c in r.harvest_calls if c["resource_type"] == "XHR"][0]
        row = self.ws.store.get_evidence_row(call["evidence_id"])
        req = json.loads(self.ws.cas.get(row["request_blob"]).decode("utf-8"))
        self.assertEqual(req["query"], [["tab", ""]])
        headers = {k.lower(): v for k, v in json.loads(row["headers_json"])}
        self.assertEqual(headers["x-pta-query-names"], "tab")
        self.assertEqual(headers["x-pta-harvest"], "cdp-network")

    def test_harvest_keeps_main_document(self):
        """主文档也算一条（它是"页面从哪来"的锚点），且与 XHR 形状不同。"""
        r = self.nav(harvest=True)
        types = [c["resource_type"] for c in r.harvest_calls]
        self.assertIn("Document", types)
        self.assertIn("XHR", types)

    def test_harvest_uses_scope_host_only(self):
        r = self.nav(harvest=True)
        hosts = {c["host"] for c in r.harvest_calls}
        self.assertEqual(hosts, {"app.test"})
        self.assertNotIn("evil.test", hosts)

    def test_harvest_does_not_add_requests(self):
        """采集是"看"，不是"发"：证据多了，但网络请求数不变。"""
        r = self.nav(harvest=True)
        self.assertEqual(r.requests_allowed, 1)   # 只有主文档真的走了 Fetch


class PlannerFeedTest(unittest.TestCase):
    """harvest 的唯一用途：让 Planner 知道"这个接口有哪些字段"，别再靠猜。"""

    def state(self, assets):
        from pta.planner import PlannerState
        return PlannerState("eng", ["app.test"], assets, [], {"requests": 0}, [])

    def test_body_fields_become_candidates(self):
        from pta.planner import Asset, heuristic_candidates
        a = Asset(url="http://app.test/api/v2/profile", method="POST",
                  body_params=("displayName", "role"))
        cands = heuristic_candidates(self.state([a]))
        pairs = {(c.template_id, c.param_path) for c in cands}
        self.assertIn(("mass-assignment-privilege", "body:*"), pairs)
        self.assertIn(("idor-write-object", "body:displayName"), pairs)

    def test_plain_body_field_generates_nothing(self):
        from pta.planner import Asset, heuristic_candidates
        a = Asset(url="http://app.test/api/v2/search", method="POST",
                  body_params=("cursor", "page_size"))
        cands = heuristic_candidates(self.state([a]))
        self.assertEqual([c for c in cands if c.param_path and c.param_path.startswith("body:")],
                         [], [c.to_json() for c in cands])

    def test_asset_json_exposes_body_params(self):
        from pta.planner import Asset
        a = Asset(url="http://app.test/x", method="POST", body_params=("role",))
        self.assertEqual(a.to_json()["body_params"], ["role"])


class HarvestFeedsPlannerTest(WorkspaceCase):
    """端到端：导航采到的接口字段直接进候选列表。"""

    setUp = _harvest_setup
    nav = _harvest_nav

    def test_harvest_feeds_heuristic_planner(self):
        from pta.planner import PlannerState, heuristic_candidates
        r = self.nav(harvest=True)
        self.assertTrue(r.harvested)
        state = PlannerState.collect(self.ws)
        posts = [a for a in state.assets if a.method == "POST"]
        self.assertTrue(posts, [a.to_json() for a in state.assets])
        self.assertIn("role", posts[0].body_params)
        cands = heuristic_candidates(state)
        self.assertIn("mass-assignment-privilege", {c.template_id for c in cands})


if __name__ == "__main__":
    unittest.main()
