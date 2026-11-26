"""邻接图演示：同一资源换方法 / 同模板换对象 / 父子资源，以及跨主机不连。

这里不跑真请求，只跑图：输入是 Planner 已经收集到的资产（URL + 方法 + 状态 + 身份），
输出是"还值得试什么"。判定链一行没改——图只负责提候选。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import graph  # noqa: E402
from pta.planner import Asset, PlannerState, heuristic_candidates  # noqa: E402


def asset(url, method="GET", status=200, identity="A", body=b"", ctype=None):
    return Asset(url=url, method=method, status=status, identity=identity,
                 body=body, content_type=ctype)


def show(g, title):
    print("\n%s" % title)
    print("  %s" % g.summary())
    for e in g.edges:
        src = g.nodes[e.src]
        if e.kind in ("refers_to", "param_ref"):
            how = "从响应体里读到的引用" if e.kind == "refers_to" else "URL 里带真值的 id"
            print("  边 %-15s %s %s  --→  %s（%s）"
                  % (e.kind, src.method, src.url, e.dst_url, how))
            print("     理由：%s" % e.reason)
            continue
        dst = g.nodes[e.dst]
        print("  边 %-15s %s %s  ←→  %s %s"
              % (e.kind, src.method, src.url, dst.method, dst.url))
        print("     理由：%s" % e.reason)
    for c in graph.candidates(g):
        print("  候选 %-22s %s %s  p=%.2f"
              % (c.template_id, c.method, c.url, c.priority))
        print("     理由：%s" % c.rationale)
    return g


def main():
    failed = []

    # ① 同一资源换方法：GET 读到过数据，PUT 试过被拒（405）
    g1 = show(graph.build([
        asset("http://app.test/api/users/7"),
        asset("http://app.test/api/users/7", "PUT", status=405),
    ]), "① 同一资源换方法（GET 200 / PUT 405）")
    write = [c for c in graph.candidates(g1) if c.template_id == "idor-write-object"]
    if len(write) != 1 or write[0].method != "PUT" or write[0].param_path != "body:*":
        failed.append("① 应该出 1 条 PUT 写候选，实际 %d 条" % len(write))
    if write and not (0.5 < write[0].priority <= 0.62):
        failed.append("① 写候选优先级应低于规则候选（≤0.62），实际 %.2f" % write[0].priority)

    # ② 同模板换对象：7 和 8 都读到了，6 与 9 还没试
    g2 = show(graph.build([
        asset("http://app.test/api/users/7"),
        asset("http://app.test/api/users/8"),
    ]), "② 同模板换对象（/users/7、/users/8 都是 200）")
    urls = sorted(c.url for c in graph.candidates(g2))
    if urls != ["http://app.test/api/users/6", "http://app.test/api/users/9"]:
        failed.append("② 应该只提 /users/6 与 /users/9，实际 %s" % urls)

    # ③ 父子资源：集合可读，单个对象被拒
    g3 = show(graph.build([
        asset("http://app.test/api/users"),
        asset("http://app.test/api/users/7", status=403),
    ]), "③ 父子资源（集合 200 / 单对象 403）")
    child = [c for c in graph.candidates(g3) if "父子关系" in c.rationale]
    if len(child) != 1 or child[0].url != "http://app.test/api/users/1":
        failed.append("③ 应该提 /users/1 一条，实际 %s"
                      % [c.url for c in child])

    # ④ 跨主机不连：两个站都有 /users/7，它们之间没有任何可外推的关系
    #    （各自仍会往自己的相邻 id 外推，那是在同一主机内）
    g4 = show(graph.build([
        asset("http://app.test/api/users/7"),
        asset("http://admin.test/api/users/7"),
    ]), "④ 跨主机不连（app.test 与 admin.test 的同名路径）")
    if g4.edges:
        failed.append("④ 跨主机不该连边，实际 %d 条边" % len(g4.edges))
    if any("app.test" in c.url and "admin.test" in c.url for c in graph.candidates(g4)):
        failed.append("④ 候选不该跨主机拼接")

    # ⑤ 引用关系：订单的响应里写着 user_id=3，而站点上确实有 /api/users/{id}
    order = b'{"id": 9, "user_id": 3, "owner_id": 3, "request_id": "8f1c2d", "title": "x"}'
    g5 = show(graph.build([
        asset("http://app.test/api/orders/9", body=order, ctype="application/json"),
        asset("http://app.test/api/users/7"),
    ]), "⑤ 引用关系（订单响应里的 user_id / owner_id）")
    refs = graph.extract_refs(order, "application/json")
    print("  抽出的引用：%s" % ", ".join("%s=%s" % (p, v) for p, _s, v in refs))
    if [p for p, _s, _v in refs].count("request_id"):
        failed.append("⑤ request_id 是跟踪号，不该当引用")
    ref_cands = [c for c in graph.candidates(g5) if "引用关系" in c.rationale]
    if [c.url for c in ref_cands] != ["http://app.test/api/users/3"]:
        failed.append("⑤ 应该提 /users/3 一条，实际 %s" % [c.url for c in ref_cands])

    # ⑥ 引用目标不存在对应资源时，不连边（宁可漏，也不造 URL）
    g6 = graph.build([
        asset("http://app.test/api/orders/9",
              body=b'{"warehouse_id": 4}', ctype="application/json"),
        asset("http://app.test/api/orders/8"),
    ])
    show(g6, "⑥ 引用落不下去（站点上没有 warehouses 这个资源）")
    if "refers_to" in [e.kind for e in g6.edges]:
        failed.append("⑥ 没有对应资源模板时不该连 ref 边")

    # ⑦ id 复用：URL 里写着 user_id=7，说明 7 号用户在这个站上是活的。
    #    这条路只有浏览器抓到的调用才带真值（我们自己的证据 query 值是空的）。
    g7 = show(graph.build([
        asset("http://app.test/api/orders?id=9&user_id=7"),
        asset("http://app.test/api/users/7"),
    ]), "⑦ id 复用（harvest 的 ?user_id=7 指向 /api/users/7）")
    print("  抽出的引用参数：%s"
          % ", ".join("%s=%s" % (n, v) for n, _s, v in graph.param_refs(
              "http://app.test/api/orders?id=9&user_id=7")))
    if not [e for e in g7.edges if e.kind == "param_ref"]:
        failed.append("⑦ ?user_id=7 应该连出一条 param_ref 边")
    # 裸 id 是自己的标识，不算引用
    g7b = graph.build([asset("http://app.test/api/orders?id=7"),
                       asset("http://app.test/api/users/9")])
    if [e for e in g7b.edges if e.kind == "param_ref"]:
        failed.append("⑦ 裸 id 不该当引用")
    # 目标已经是已知资产，不重复提候选
    id_cands = [c for c in graph.candidates(g7, max_out=20) if "id 复用" in c.rationale]
    if id_cands:
        failed.append("⑦ /users/7 已经探过，不该重复提，实际 %s"
                      % [c.url for c in id_cands])
    print("  候选：已知资产不重复提 → %d 条" % len(id_cands))

    # ⑧ Planner 实际用图提候选：只有一条 GET 资产，规则一个字都命中不了
    state = PlannerState("ENG-DEMO", ("app.test",),
                         [asset("http://app.test/api/users/7")],
                         [], {"used": 3, "max": 200}, [])
    cands = heuristic_candidates(state)
    print("\n⑧ Planner 候选（规则 + 图）")
    for c in cands:
        print("  %-22s %s %-32s p=%.2f  来源=%s"
              % (c.template_id, c.method, c.url, c.priority, c.source))
    sources = {c.source for c in cands}
    if "graph" not in sources:
        failed.append("⑧ 图候选没有进最终列表，来源只有 %s" % sources)
    if cands and any(c.priority > cands[0].priority for c in cands):
        failed.append("⑧ 候选没有按优先级排序")

    # ⑨ 候选池被规则候选占满时，图外推仍然占到位子（否则特性等于没写）
    many = [asset("http://app.test/api/items%d?id=5" % i) for i in range(10)]
    many += [asset("http://app.test/api/users/7"), asset("http://app.test/api/users/8")]
    state9 = PlannerState("ENG-DEMO", ("app.test",), many, [],
                          {"used": 0, "max": 200}, [])
    narrow = heuristic_candidates(state9, max_candidates=5, graph_slots=2)
    squeezed = heuristic_candidates(state9, max_candidates=5, graph_slots=0)
    print("\n⑨ 位子只有 5 个时：graph_slots=2 → 图候选 %d 条；=0 → %d 条"
          % (sum(1 for c in narrow if c.source == "graph"),
             sum(1 for c in squeezed if c.source == "graph")))
    if sum(1 for c in narrow if c.source == "graph") != 2:
        failed.append("⑨ 留了 2 个位子，图候选就该有 2 条")
    if any(c.source == "graph" for c in squeezed):
        failed.append("⑨ graph_slots=0 时不该再硬塞图候选")

    print()
    if failed:
        for f in failed:
            print("FAIL %s" % f)
        print("结果：FAIL")
        return 1
    print("结果：OK（图只把已有证据外推一步；跨主机不连，已知资产不重复探）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
