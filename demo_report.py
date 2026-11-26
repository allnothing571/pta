"""第 9 项演示：单文件 HTML 报告 + 多轮（engagement）合并。

"报告"这件事只有两条硬要求，其余都是排版：
1. 发出去就能看 —— 所以 HTML 必须单文件，不许引用任何外部 CSS/JS/字体；
2. 合并多轮时每条结论必须自带轮次 —— 否则两轮的同名模板会被读成"重复上报"。

这里还顺手证明一件事：`export_report` 写出来的 manifest 里 `engagements`
就是"这一份报告覆盖了哪几轮"，和 findings.json 里逐条的 `engagement` 对得上。

跑法：python demo_report.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta.probe import ProbeRequest  # noqa: E402
from pta.report import ReportOptions, export_report  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockRoute, MockTransport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
OBJECT = json.dumps({"id": 1, "name": "widget", "owner": "A"}, sort_keys=True).encode("utf-8")
ROUTES = [MockRoute("GET", "app.test", "/api/users/1", 200,
                    (("Content-Type", "application/json"),), OBJECT)]


def open_eng(root, engrail, transport):
    """把 scope.json 的 engagement_id 换掉再打开——等于"'另一天再跑一轮'"。"""
    path = os.path.join(root, "scope.json")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data["engagement_id"] = engrail
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return open_workspace(root, transport=transport,
                          dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))


def round_one(ws, eng, title, status, confidence):
    res = ws.probe.run(ProbeRequest(action_id="a-" + eng, url="http://app.test/api/users/1",
                                    identity="B", label="probe-B"))
    assert res.status == "ok", res.reason
    ws.store.put_finding({
        "id": ("f" + eng.replace("-", "") + status)[:24],
        "engagement_id": eng, "template_id": "idor-object-ref", "title": title,
        "status": status, "confidence": confidence, "evidence_ids": [res.evidence_id],
        "verdict": {"rationale": "B 身份读到了 A 的对象", "metrics": {"similarity": 0.97}},
        "created_at": "2026-04-01T00:00:00Z",
    })
    return res.evidence_id


def main():
    root = os.path.join(tempfile.gettempdir(), "pta-demo-report")
    shutil.rmtree(root, ignore_errors=True)
    out = os.path.join(root, "out")
    ok = True
    try:
        init_workspace(root, Scope(engagement_id="ENG-R1", domains=("app.test",),
                                   allow_private=True, rate_per_host=200, max_requests=200))

        ws1 = open_eng(root, "ENG-R1", MockTransport(ROUTES))
        round_one(ws1, "ENG-R1", "第一轮：对象引用越权", "confirmed", 0.97)

        ws2 = open_eng(root, "ENG-R2", MockTransport(ROUTES))
        round_one(ws2, "ENG-R2", "第二轮：同一处再看一次", "hypothesis", 0.72)

        print("=" * 78)
        print("第 9 项：单文件 HTML 报告 + 多轮合并")
        print("=" * 78)
        print("库里的轮次：%s" % [r["id"] for r in ws2.store.list_engagements()])

        manifest = export_report(ws2, out, ReportOptions(html=True),
                                 generated_at="2026-04-02T00:00:00Z")
        print()
        print("① 默认只导当前轮")
        print("   engagements=%s  findings=%d"
              % (manifest["engagements"], manifest["counts"]["findings"]))

        manifest = export_report(ws2, out, ReportOptions(
            html=True, engagements=("ENG-R1", "ENG-R2")), generated_at="2026-04-02T00:00:00Z")
        with open(os.path.join(out, "findings.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        with open(os.path.join(out, "report.html"), encoding="utf-8") as fh:
            page = fh.read()
        with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
            md = fh.read()

        print()
        print("② 合并两轮")
        print("   engagements=%s  findings=%d" % (manifest["engagements"],
                                                 manifest["counts"]["findings"]))
        for f in data["findings"]:
            print("   - %-8s %-10s %.3f  %s" % (f["engagement"], f["status"],
                                                f["confidence"], f["title"]))
        print("   Markdown 标题：%s" % md.splitlines()[0])
        print("   每条都有轮次：%s" % all(("- 轮次：`%s`" % f["engagement"]) in md
                                          for f in data["findings"]))

        print()
        print("③ 单文件 HTML 自检")
        print("   report.html %d 字节，外部资源引用 %d 处"
              % (len(page.encode("utf-8")),
                 sum(page.count(x) for x in ("<link", "<script src", "http://", "https://"))))
        print("   含 doctype=%s  含两轮 id=%s"
              % (page.lower().startswith("<!doctype html>"),
                 ("ENG-R1" in page and "ENG-R2" in page)))

        print()
        print("④ manifest 指纹（整包可校验）")
        print("   root_sha256=%s…  files=%d"
              % (manifest["root_sha256"][:16], manifest["counts"]["files"]))
        print("   证据重算：%d / %d 一致；结论绑证据：%d / %d"
              % (manifest["verify"]["evidence_ok"], manifest["verify"]["evidence_checked"],
                 manifest["verify"]["findings_bound"], manifest["counts"]["findings"]))

        checks = [
            manifest["engagements"] == ["ENG-R1", "ENG-R2"],
            manifest["counts"]["findings"] == 2,
            all("engagement" in f for f in data["findings"]),
            "等 2 轮" in md,
            page.lower().startswith("<!doctype html>"),
            sum(page.count(x) for x in ("<link", "<script src", "http://", "https://")) == 0,
            "ENG-R1" in page and "ENG-R2" in page,
            manifest["verify"]["evidence_ok"] == manifest["verify"]["evidence_checked"],
        ]
        ok = all(checks)
        if not ok:
            print()
            print("   自检失败：%s" % [i for i, c in enumerate(checks, 1) if not c])
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print()
    print("结果：%s（HTML 单文件可直接发；合并时每条结论自带轮次）" % ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
