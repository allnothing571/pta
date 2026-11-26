"""多项目壳演示：台账 → 阶段 → 详情 → 筛选 → 交付 → 后台任务 → HTTP 层。

全程离线（假 DNS + MockTransport），最后一行必须是 OK。
想在人肉浏览器里点：python demo_projects.py --serve（默认 127.0.0.1:8766）
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pta import projects as proj                       # noqa: E402
from pta import targets                                # noqa: E402
from pta.api import make_server                        # noqa: E402
from pta.events import Bus                             # noqa: E402
from pta.probe import ProbeRequest                     # noqa: E402
from pta.scope import DnsPin, Scope                    # noqa: E402
from pta.transport import MockRoute, MockTransport      # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ROUTES = [MockRoute("GET", "app.test", "/ping", 200,
                    (("Content-Type", "text/plain"),), b"pong")]


def step(n, title):
    print("\n[%d] %s" % (n, title))


def check(label, ok, extra=""):
    print("    %s %s%s" % ("OK " if ok else "!! ", label, (" — " + extra) if extra else ""))
    return ok


def finding(fid, status, conf):
    return {"id": fid, "engagement_id": "", "template_id": "idor-object-ref",
            "title": "对象直读", "status": status, "confidence": conf,
            "evidence_ids": [], "verdict": {"metrics": {}, "rationale": "demo"},
            "created_at": "2026-11-13T00:00:00Z"}


def mk(tmp, name, identities=("A",), evidence=1, hits=(), parent="labs"):
    root = os.path.join(tmp, parent, name)
    scope = Scope(engagement_id="ENG-" + name.upper(), domains=("app.test",),
                  allow_private=True, rate_per_host=1000.0, max_requests=5000,
                  allowed_ports=(80, 443, 8080))
    init_workspace(root, scope)
    ws = open_workspace(root, transport=MockTransport(ROUTES),
                        dns=DnsPin(resolver=lambda host: [PUBLIC_IP]))
    for ident in identities:
        ws.vault.put("cred/%s/authorization" % ident, "Bearer TOKEN-" + ident)
    for i in range(evidence):
        ws.probe.run(ProbeRequest(action_id="e%d" % i, url="http://app.test/ping?i=%d" % i,
                                  identity=(identities or ["none"])[0], label="probe"))
    for rec in hits:
        row = dict(rec)
        row["engagement_id"] = scope.engagement_id
        ws.store.put_finding(row)
    ws.store.close()
    targets.register(root, engagement_id=scope.engagement_id, domains=("app.test",),
                     alias=name, name=name)
    return root


def table(rows):
    print("    %-8s %-12s %-14s %s" % ("alias", "名字", "阶段", "卡在哪"))
    for r in rows:
        print("    %-8s %-12s %-14s %s" % (r["alias"], r["name"], r["stage_label"],
                                          (r["why"] or "")[:46]))


def get(port, path, headers=None):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), headers=headers or {})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="pta-demo-proj-")
    os.environ["PTA_HOME"] = os.path.join(tmp, "home")
    ok = True
    try:
        mk(tmp, "alpha", hits=(finding("f1", "confirmed", 0.92),))
        mk(tmp, "beta", identities=(), evidence=0)
        mk(tmp, "gamma", hits=(finding("f2", "hypothesis", 0.66),))
        mk(tmp, "delta", hits=(finding("f3", "confirmed", 0.90),), parent="clients")
        proj.deliver("delta")

        step(1, "台账里有四个项目，阶段是每次现算的")
        out = proj.listing()
        table(out["projects"])
        ok &= check("四个项目都在", out["total"] == 4, "total=%d" % out["total"])
        stages = {r["alias"]: r["stage"] for r in out["projects"]}
        ok &= check("阶段各就各位",
                    stages == {"alpha": "deliverable", "beta": "no_identity",
                               "gamma": "review", "delta": "delivered"},
                    str(stages))

        step(2, "筛选口径：工作区是父目录，阶段计数在过滤之前算")
        print("    工作区：", [os.path.basename(w) for w in out["workspaces"]])
        print("    阶段计数：", [(s["id"], s["count"]) for s in out["stages"] if s["count"]])
        only_inflight = proj.listing(stages=("inflight",))
        facet = {s["id"]: s["count"] for s in only_inflight["stages"]}
        print("    stage=inflight ->", [r["alias"] for r in only_inflight["projects"]])
        ok &= check("进行中只剩两条", only_inflight["total"] == 2,
                    str([r["alias"] for r in only_inflight["projects"]]))
        ok &= check("计数没被过滤吃掉", facet["deliverable"] == 1 and facet["delivered"] == 1,
                    "deliverable=%d delivered=%d" % (facet["deliverable"], facet["delivered"]))
        by_ws = proj.listing(workspace=os.path.join(tmp, "clients"))
        ok &= check("按工作区筛", [r["alias"] for r in by_ws["projects"]] == ["delta"])

        step(3, "详情：六步时间线 + 一句话原因 + 该给哪几个按钮")
        d = proj.detail("gamma")
        print("    %s · %s" % (d["project"]["name"], d["stage_label"]))
        for s in d["steps"]:
            print("      [%-7s] %-10s %s" % (s["state"], s["id"], s["detail"]))
        print("    为什么停：", d["why"])
        print("    按钮：", [a["label"] for a in d["next"]])
        ok &= check("只有一个 current",
                    [s["state"] for s in d["steps"]].count("current") == 1)
        ok &= check("卡在 review 且指向复核",
                    d["stage"] == "review" and d["next"][0]["kind"] == "review")

        step(4, "交付：说得出为什么不能交；强制要留痕；能撤回")
        try:
            proj.deliver("beta")
            ok &= check("不该能交付", False)
        except proj.ProjectError as exc:
            print("    拒绝：%s" % exc.message)
            ok &= check("拒绝时带阶段与原因",
                        exc.code == "not_deliverable" and exc.extra.get("stage") == "no_identity")
        proj.deliver("beta", force=True, note="客户要个半成品")
        row = targets.get("beta")
        print("    beta 现在：%s" % proj.summarize(row)["stage_label"])
        ok &= check("强制交付落库且留痕",
                    proj.summarize(row)["stage"] == "delivered" and "强制交付" in
                    (row.get("delivered_note") or ""))
        proj.deliver("beta", delivered=False)
        ok &= check("撤回后回到原阶段",
                    proj.summarize(targets.get("beta"))["stage"] == "no_identity")

        step(5, "后台任务：一个项目同时只跑一个，进度只留最近 20 条")
        bus = Bus()
        reg = proj.JobRegistry(bus=bus, limit=2)
        q = bus.subscribe()
        gate = threading.Event()

        def work(job):
            job.note("侦察 app.test")
            gate.wait(3)
            job.note("收了 12 个接口")
            return {"pages": 12}

        job = reg.start("alpha", "recon", "侦察", work)
        print("    事件：", q.get(timeout=3)["type"])
        try:
            reg.start("alpha", "round", "跑一轮", lambda j: None)
            ok &= check("第二个任务应当被挡", False)
        except proj.JobBusy as exc:
            ok &= check("第二个任务被挡", exc.job.alias == "alpha")
        gate.set()
        deadline = time.time() + 5
        while time.time() < deadline and job.state in ("queued", "running"):
            time.sleep(0.02)
        print("    状态：%s，结果：%s" % (job.state, job.result))
        print("    进度：", [p.split(" ", 1)[-1] for p in job.progress])
        ok &= check("跑完且结果带回来", job.state == "done" and job.result == {"pages": 12})
        ok &= check("结束事件带项目名",
                    q.get(timeout=3).get("project") == "alpha")

        step(6, "把已经有 scope.json 的目录收编进台账（不重写别人写好的边界）")
        legacy = os.path.join(tmp, "legacy-box")
        init_workspace(legacy, Scope(engagement_id="LEGACY", domains=("10.0.0.5",),
                                     allow_private=True, rate_per_host=5.0,
                                     max_requests=900, allowed_ports=(80, 8080)))
        adopted = proj.create("老盒子", "http://10.0.0.5:8080/", legacy)
        print("    imported=%s engagement=%s"
              % (adopted["created"]["imported"], adopted["created"]["engagement_id"]))
        ok &= check("收编不改边界",
                    adopted["created"]["imported"] and
                    adopted["created"]["engagement_id"] == "LEGACY")

        step(7, "HTTP 层：同一个台账，三个视图要的字段都在")
        httpd, _ = make_server(proj.ProjectBook(), host="127.0.0.1", port=0)
        port = httpd.server_port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        listing = get(port, "/api/projects")
        print("    GET /api/projects -> total=%s, stages=%d 档"
              % (listing["total"], len(listing["stages"])))
        detail = get(port, "/api/projects/alpha")
        state = get(port, "/api/state", {"X-Pta-Project": "alpha"})
        jobs = get(port, "/api/jobs?project=alpha")
        print("    GET /api/projects/alpha -> %s, 按钮 %s"
              % (detail["stage_label"], [a["label"] for a in detail["next"]]))
        print("    GET /api/state (X-Pta-Project) -> engagement=%s" % state["engagement"])
        httpd.shutdown()
        ok &= check("列表/详情/状态都能按项目取",
                    listing["total"] == 5 and detail["stage"] == "deliverable"
                    and state["engagement"] == "ENG-ALPHA")
        ok &= check("任务接口可用", isinstance(jobs["jobs"], list))

        if "--serve" in sys.argv:
            httpd, _ = make_server(proj.ProjectBook(), host="127.0.0.1", port=8766)
            print("\n操作台: http://127.0.0.1:8766/   （Ctrl+C 结束）")
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n收工。")
            return 0
    finally:
        shutil.rmtree(tmp, True)

    print("\n结果: %s" % ("OK（台账 / 阶段 / 详情 / 筛选 / 交付 / 任务 / HTTP 全通）"
                          if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
