"""资产邻接图：URL 归一化、三类边、候选展开与克制边界。

这些用例不需要工作区：图是纯函数（资产列表进，节点边出）。
只有最后一组验证 Planner 真的用上了图。
"""
import unittest

from pta import graph
from pta.planner import Asset, PlannerState, heuristic_candidates


def asset(url, method="GET", status=200, identity="A", body=b"", ctype=None):
    return Asset(url=url, method=method, status=status, identity=identity,
                 body=body, content_type=ctype)


class ResourceKeyTest(unittest.TestCase):
    def test_numeric_segment_becomes_placeholder(self):
        self.assertEqual(graph.resource_key("http://a.test/api/users/7"),
                         "/api/users/{id}")

    def test_first_segment_is_never_an_id(self):
        # /7/users 里的 7 不像"某个对象的 id"，它更像版本号或租户号
        self.assertEqual(graph.resource_key("http://a.test/7/users"), "/7/users")

    def test_uuid_and_object_id(self):
        self.assertEqual(
            graph.resource_key("http://a.test/api/orders/8f1c2d9e-1b2a-4c3d-9e8f-0a1b2c3d4e5f"),
            "/api/orders/{id}")
        self.assertEqual(
            graph.resource_key("http://a.test/api/items/507f1f77bcf86cd799439011"),
            "/api/items/{id}")

    def test_id_query_is_masked_and_sorted(self):
        self.assertEqual(graph.resource_key("http://a.test/api/users?id=7&tab=x"),
                         "/api/users?id={id}&tab=x")

    def test_plain_query_values_are_kept(self):
        self.assertEqual(graph.resource_key("http://a.test/search?q=admin"),
                         "/search?q=admin")

    def test_trailing_slash_is_kept(self):
        self.assertEqual(graph.resource_key("http://a.test/api/users/7/"),
                         "/api/users/{id}/")


class ObjectIdTest(unittest.TestCase):
    def test_slots_cover_path_and_query(self):
        slots = graph._object_ids("http://a.test/api/users/7?org=3&id=42")
        # 段序号是路径段下标：0=api, 1=users, 2=7
        self.assertIn(("seg:2", "7"), slots)
        self.assertIn(("query:id", "42"), slots)
        # org 不是 id 类参数名，不算对象
        self.assertNotIn("query:org", [s for s, _ in slots])

    def test_replace_one_segment_keeps_the_rest(self):
        out = graph.replace_object_id("http://a.test/api/users/7/orders/3", "seg:2", "8")
        # seg 序号按路径段下标算：0=api, 1=users, 2=7
        self.assertEqual(out, "http://a.test/api/users/8/orders/3")

    def test_replace_query_value(self):
        out = graph.replace_object_id("http://a.test/api/users?id=7&tab=x", "query:id", "8")
        self.assertEqual(out, "http://a.test/api/users?id=8&tab=x")

    def test_bump_only_for_numbers(self):
        self.assertEqual(graph._bump("7", 1), "8")
        self.assertEqual(graph._bump("7", -1), "6")
        self.assertIsNone(graph._bump("1", -1))          # 没有 0 号对象
        self.assertIsNone(graph._bump("8f1c2d9e", 1))    # 非数字没有"下一个"


class BuildTest(unittest.TestCase):
    def test_same_resource_when_methods_differ(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://a.test/api/users/7", "PUT")])
        kinds = [e.kind for e in g.edges]
        self.assertEqual(kinds, ["same_resource"])

    def test_sibling_object_when_ids_differ(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://a.test/api/users/8")])
        self.assertEqual([e.kind for e in g.edges], ["sibling_object"])

    def test_child_resource_parent_to_child(self):
        g = graph.build([asset("http://a.test/api/users"),
                         asset("http://a.test/api/users/7")])
        edge = g.edges[0]
        self.assertEqual(edge.kind, "child_resource")
        self.assertEqual(g.nodes[edge.src].url, "http://a.test/api/users")
        self.assertEqual(g.nodes[edge.dst].url, "http://a.test/api/users/7")

    def test_no_edge_across_hosts(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://b.test/api/users/8")])
        self.assertEqual(g.edges, [])

    def test_duplicate_edges_are_collapsed(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://a.test/api/users/7", "PUT")])
        g.link(graph.Edge("same_resource", g.edges[0].dst, g.edges[0].src, "反着说一遍"))
        self.assertEqual(len(g.edges), 1)

    def test_same_url_same_method_is_one_node(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://a.test/api/users/7")])
        self.assertEqual(len(g.nodes), 1)
        self.assertEqual(g.edges, [])

    def test_brief_counts_kinds(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://a.test/api/users/8")])
        brief = g.brief()
        self.assertEqual(brief["nodes"], 2)
        self.assertEqual(brief["edges"], 1)
        self.assertEqual(brief["kinds"], {"sibling_object": 1})

    def test_default_port_is_the_same_host(self):
        # 证据表里 URL 一律带端口（:80），浏览器抓到的是页面里写的那样（不带）：
        # 不归一的话这两条会被当成两个站，父子边就断了
        g = graph.build([asset("http://a.test:80/api/users"),
                         asset("http://a.test/api/users/7")])
        self.assertEqual([e.kind for e in g.edges], ["child_resource"])

    def test_default_port_variant_is_not_another_object(self):
        g = graph.build([asset("http://a.test:80/api/users/7"),
                         asset("http://a.test/api/users/7")])
        self.assertEqual(g.edges, [])          # 同一条资产，不是"另一个对象"

    def test_host_key_keeps_non_default_ports(self):
        self.assertEqual(graph.host_key("https://a.test:443/x"), "a.test")
        self.assertEqual(graph.host_key("http://A.test:80/x"), "a.test")
        self.assertEqual(graph.host_key("http://a.test:8080/x"), "a.test:8080")


class CandidateTest(unittest.TestCase):
    def test_same_resource_yields_write_candidate(self):
        g = graph.build([asset("http://a.test/api/users/7", status=200),
                         asset("http://a.test/api/users/7", "PUT", status=405)])
        cands = graph.candidates(g)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0].template_id, "idor-write-object")
        self.assertEqual(cands[0].method, "PUT")
        self.assertEqual(cands[0].param_path, "body:*")
        self.assertIn("换个方法", cands[0].rationale)

    def test_write_candidate_needs_a_readable_reader(self):
        # PUT 先被观察到、GET 拿到 403：没有"这个资源能读"的证据，不外推写
        g = graph.build([asset("http://a.test/api/users/7", "PUT"),
                         asset("http://a.test/api/users/7", status=403)])
        self.assertEqual(graph.candidates(g), [])

    def test_sibling_yields_neighbour_ids(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://a.test/api/users/8")])
        cands = graph.candidates(g)
        # 7 的邻居 6/8、8 的邻居 7/9；7 和 8 本身就是已知资产，不再当读候选
        self.assertEqual(sorted(c.url for c in cands),
                         ["http://a.test/api/users/6",
                          "http://a.test/api/users/9"])
        self.assertTrue(all(c.template_id == "idor-object-ref" for c in cands))
        self.assertTrue(all(c.param_path is None for c in cands))

    def test_child_yields_single_candidate(self):
        g = graph.build([asset("http://a.test/api/users"),
                         asset("http://a.test/api/users/7")])
        cands = graph.candidates(g)
        self.assertEqual(len(cands), 1)
        # 集合可读 → 试它下面的第一条对象；已有的 /users/7 不再重复探
        self.assertEqual(cands[0].url, "http://a.test/api/users/1")
        self.assertIn("父子关系", cands[0].rationale)

    def test_priorities_stay_below_rule_candidates(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://a.test/api/users/7", "PUT"),
                         asset("http://a.test/api/users/8")])
        cands = graph.candidates(g)
        self.assertTrue(cands)
        self.assertLessEqual(max(c.priority for c in cands), 0.62)

    def test_empty_graph_is_empty(self):
        self.assertEqual(graph.candidates(graph.build([])), [])
        self.assertEqual(graph.candidates(None), [])

    def test_summary_counts_edges(self):
        g = graph.build([asset("http://a.test/api/users/7"),
                         asset("http://a.test/api/users/8")])
        self.assertIn("2 个资产", g.summary())


class RefTest(unittest.TestCase):
    """refers_to：从响应体里读"这个对象引用了谁"。"""

    def refs(self, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        return graph.extract_refs(body, ctype)

    def test_extracts_foreign_key_fields(self):
        out = self.refs('{"id": 9, "user_id": 3, "title": "x"}')
        self.assertEqual(out, [("user_id", "user", "3")])   # 裸 id 是自己的标识，不是引用

    def test_nested_and_array_values(self):
        out = self.refs('{"items": [{"product_id": 11}, {"product_id": "12"}]}')
        self.assertEqual([(p, s, v) for p, s, v in out],
                         [("items[0].product_id", "product", "11"),
                          ("items[1].product_id", "product", "12")])

    def test_noise_fields_are_ignored(self):
        out = self.refs('{"request_id": "8f1c", "trace_id": 5, "session_id": 7}')
        self.assertEqual(out, [])

    def test_non_json_is_ignored(self):
        self.assertEqual(self.refs("<div data-user-id='3'></div>", "text/html"), [])
        self.assertEqual(self.refs(b"\x00\x01binary", "application/x-java-serialized-object"), [])

    def test_broken_json_is_ignored(self):
        self.assertEqual(self.refs('{"user_id": '), [])

    def test_edge_and_candidate_when_resource_exists(self):
        g = graph.build([
            asset("http://app.test/api/orders/9",
                  body=b'{"id": 9, "user_id": 3}', ctype="application/json"),
            asset("http://app.test/api/users/7"),      # 提供 /api/users/{id} 这个模板
        ])
        kinds = [e.kind for e in g.edges]
        self.assertIn("refers_to", kinds)
        ref_edge = [e for e in g.edges if e.kind == "refers_to"][0]
        self.assertEqual(ref_edge.dst_url, "http://app.test/api/users/3")

        cands = [c for c in graph.candidates(g, max_out=20) if "引用关系" in c.rationale]
        self.assertEqual([c.url for c in cands], ["http://app.test/api/users/3"])
        self.assertEqual(cands[0].priority, 0.42)

    def test_ref_candidate_ranks_last(self):
        # 引用边的优先级最低：max_out 截断时先牺牲它，规则命中与结构边排在前面
        g = graph.build([
            asset("http://app.test/api/orders/9",
                  body=b'{"user_id": 3}', ctype="application/json"),
            asset("http://app.test/api/users/7"),
        ])
        cands = graph.candidates(g, max_out=20)
        self.assertEqual(cands[-1].priority, 0.42)

    def test_no_edge_when_resource_is_unknown(self):
        # 站点上没有 /api/users/{id} 这样的资源，就落不成具体 URL
        g = graph.build([
            asset("http://app.test/api/orders/9",
                  body=b'{"user_id": 3}', ctype="application/json"),
            asset("http://app.test/api/orders/8"),
        ])
        self.assertNotIn("refers_to", [e.kind for e in g.edges])

    def test_no_edge_across_hosts(self):
        # 另一个站上的 /api/users/{id} 在这台机器上打出去只是 404
        g = graph.build([
            asset("http://app.test/api/orders/9",
                  body=b'{"user_id": 3}', ctype="application/json"),
            asset("http://b.test/api/users/7"),
        ])
        self.assertNotIn("refers_to", [e.kind for e in g.edges])

    def test_alias_maps_owner_to_users(self):
        g = graph.build([
            asset("http://app.test/api/orders/9",
                  body=b'{"owner_id": 3}', ctype="application/json"),
            asset("http://app.test/api/users/7"),
        ])
        ref = [e for e in g.edges if e.kind == "refers_to"]
        self.assertEqual(len(ref), 1)
        self.assertEqual(ref[0].dst_url, "http://app.test/api/users/3")

    def test_known_target_is_not_proposed_again(self):
        g = graph.build([
            asset("http://app.test/api/orders/9",
                  body=b'{"user_id": 7}', ctype="application/json"),
            asset("http://app.test/api/users/7"),      # 正好就是引用目标，已经探过
        ])
        self.assertEqual([c for c in graph.candidates(g, max_out=20)
                          if "引用关系" in c.rationale], [])

    def test_body_is_optional(self):
        g = graph.build([asset("http://app.test/api/users/7")])
        self.assertEqual([e.kind for e in g.edges], [])


class ParamRefTest(unittest.TestCase):
    """param_ref：URL 查询里的 `?user_id=7` 说明这个对象是活的。

    这条路只在走浏览器（harvest）之后才有货：我们自己发的请求 query 值一律留空。
    """

    def param_edges(self, g):
        return [e for e in g.edges if e.kind == "param_ref"]

    def test_query_id_param_links_to_existing_resource(self):
        g = graph.build([asset("http://app.test/api/orders?user_id=7"),
                         asset("http://app.test/api/users/9")])
        ref = self.param_edges(g)
        self.assertEqual(len(ref), 1)
        self.assertEqual(ref[0].dst_url, "http://app.test/api/users/7")

    def test_bare_id_is_not_a_reference(self):
        # 裸 id 是"这个对象自己"，不是对别人的引用
        g = graph.build([asset("http://app.test/api/orders?id=7"),
                         asset("http://app.test/api/users/9")])
        self.assertEqual(self.param_edges(g), [])

    def test_blank_value_gives_nothing(self):
        # 证据表里的 query 值留空，这条边因此永远为空——正是"只有 harvest 才连得上"
        g = graph.build([asset("http://app.test/api/orders?user_id="),
                         asset("http://app.test/api/users/9")])
        self.assertEqual(self.param_edges(g), [])

    def test_noise_param_is_ignored(self):
        g = graph.build([asset("http://app.test/api/orders?session_id=7"),
                         asset("http://app.test/api/sessions/9")])
        self.assertEqual(self.param_edges(g), [])

    def test_value_must_be_id_shaped(self):
        g = graph.build([asset("http://app.test/api/orders?user_id=admin"),
                         asset("http://app.test/api/users/9")])
        self.assertEqual(self.param_edges(g), [])

    def test_no_edge_without_a_matching_resource(self):
        # 站点上没有 /api/users/{id}，这个 7 就落不到任何 URL 上
        g = graph.build([asset("http://app.test/api/orders?user_id=7"),
                         asset("http://app.test/api/items/9")])
        self.assertEqual(self.param_edges(g), [])

    def test_no_edge_across_hosts(self):
        g = graph.build([asset("http://app.test/api/orders?user_id=7"),
                         asset("http://b.test/api/users/9")])
        self.assertEqual(self.param_edges(g), [])

    def test_alias_maps_owner_to_users(self):
        g = graph.build([asset("http://app.test/api/orders?owner_id=3"),
                         asset("http://app.test/api/users/9")])
        ref = self.param_edges(g)
        self.assertEqual(len(ref), 1)
        self.assertEqual(ref[0].dst_url, "http://app.test/api/users/3")

    def test_same_path_is_left_to_sibling_object(self):
        # 目标就是自己这个 URL：那是同模板换对象的事，不重复造边
        g = graph.build([asset("http://app.test/api/users/7?user_id=7")])
        self.assertEqual(self.param_edges(g), [])

    def test_candidate_priority_between_sibling_and_body_ref(self):
        g = graph.build([asset("http://app.test/api/orders?user_id=7"),
                         asset("http://app.test/api/users/9")])
        cands = [c for c in graph.candidates(g, max_out=20) if "id 复用" in c.rationale]
        self.assertEqual([c.url for c in cands], ["http://app.test/api/users/7"])
        self.assertEqual(cands[0].priority, 0.46)
        self.assertEqual(cands[0].template_id, "idor-object-ref")
        self.assertEqual(cands[0].source, "graph")

    def test_known_target_is_not_proposed_again(self):
        g = graph.build([asset("http://app.test/api/orders?user_id=7"),
                         asset("http://app.test/api/users/7")])
        self.assertEqual([c for c in graph.candidates(g, max_out=20)
                          if "id 复用" in c.rationale], [])

    def test_one_node_contributes_at_most_two(self):
        # 列表接口常带三四个 `*_id`，全展开会把候选池占满
        g = graph.build([
            asset("http://app.test/api/orders?a_id=1&b_id=2&c_id=3"),
            asset("http://app.test/api/as/9"),
            asset("http://app.test/api/bs/9"),
            asset("http://app.test/api/cs/9"),
        ])
        cands = [c for c in graph.candidates(g, max_out=20) if "id 复用" in c.rationale]
        self.assertEqual(len(cands), graph.MAX_PARAM_REF_CANDS)


class PlannerStateTest(unittest.TestCase):
    def test_state_builds_graph_from_assets(self):
        state = PlannerState("ENG", ("a.test",),
                             [asset("http://a.test/api/users/7"),
                              asset("http://a.test/api/users/8")],
                             [], {"used": 0, "max": 100}, [])
        self.assertEqual([e.kind for e in state.graph.edges], ["sibling_object"])

    def test_compact_carries_graph(self):
        state = PlannerState("ENG", ("a.test",),
                             [asset("http://a.test/api/users/7")],
                             [], {"used": 0, "max": 100}, [])
        compact = state.compact()
        self.assertIn("graph", compact)
        self.assertEqual(compact["graph"]["edge_count"], 0)

    def test_heuristic_uses_graph(self):
        # 只有一条 GET 资产、没有任何参数名命中规则；除了一条"无参端点先查产物"，
        # 其余候选只能来自图。
        state = PlannerState("ENG", ("a.test",),
                             [asset("http://a.test/api/users/7")],
                             [], {"used": 0, "max": 100}, [])
        cands = heuristic_candidates(state)
        graph_cands = [c for c in cands if c.source == "graph"]
        self.assertEqual(sorted(c.url for c in graph_cands),
                         ["http://a.test/api/users/6", "http://a.test/api/users/8"])
        self.assertTrue(all(c.template_id == "idor-object-ref" for c in graph_cands))

    def test_graph_slots_survive_a_full_pool(self):
        # 十个资产各命中一次规则（0.75），位子只有 5 个：不保留的话图外推全被挤掉
        assets = [asset("http://a.test/api/items%d?id=5" % i) for i in range(10)]
        assets += [asset("http://a.test/api/users/7"), asset("http://a.test/api/users/8")]
        state = PlannerState("ENG", ("a.test",), assets, [],
                             {"used": 0, "max": 100}, [])
        cands = heuristic_candidates(state, max_candidates=5, graph_slots=2)
        self.assertEqual(len(cands), 5)
        graph_cands = [c for c in cands if c.source == "graph"]
        self.assertEqual(len(graph_cands), 2)
        self.assertEqual(sorted(c.url for c in graph_cands),
                         ["http://a.test/api/users/6", "http://a.test/api/users/9"])

    def test_zero_slots_means_pure_priority(self):
        assets = [asset("http://a.test/api/items%d?id=5" % i) for i in range(10)]
        assets += [asset("http://a.test/api/users/7"), asset("http://a.test/api/users/8")]
        state = PlannerState("ENG", ("a.test",), assets, [],
                             {"used": 0, "max": 100}, [])
        cands = heuristic_candidates(state, max_candidates=5, graph_slots=0)
        self.assertFalse([c for c in cands if c.source == "graph"])


if __name__ == "__main__":
    unittest.main()
