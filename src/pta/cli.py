"""命令行入口。

python -m pta.cli init    --root W --engagement ENG --domain example.com [--allow-private]
python -m pta.cli probe   --root W --url URL [--identity probe] [--label idor] ...
python -m pta.cli replay  --root W --evidence-id ID
python -m pta.cli state   --root W
python -m pta.cli approve --root W --fp FP --decision approve --scope class
python -m pta.cli logs    --root W [--decision denied]
python -m pta.cli verify  --root W
python -m pta.cli show    --root W [FINDING_ID | --last] [--as curl|powershell|raw|python]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import credentials, grants, labels, vhx
from .poc import PocError
from .scope import Scope
from .workspace import init_workspace, open_workspace


def _cmd_init(args: argparse.Namespace) -> int:
    scope = Scope(
        engagement_id=args.engagement,
        domains=tuple(args.domain),
        allow_private=args.allow_private,
        egress_proxy=args.egress_proxy,
        rate_per_host=args.rate,
        max_requests=args.max_requests,
        expires_at=args.expires_at,
        allowed_ports=tuple(sorted({80, 443} | set(args.allow_port or ()))),
    )
    path = init_workspace(args.root, scope)
    out = {"ok": True, "scope": path}
    if not getattr(args, "no_register", False):
        from . import targets

        try:
            row = targets.register(args.root, engagement_id=args.engagement,
                                   domains=tuple(args.domain),
                                   alias=getattr(args, "alias", "") or "",
                                   note=getattr(args, "note", "") or "")
            out["alias"] = row.get("alias")
            out["ledger"] = targets.ledger_path()
            out["hint"] = "以后可以直接 `--root %s`" % row.get("alias")
        except targets.LedgerError as exc:
            # 登记失败不该让 init 失败：工作区本身已经建好了
            out["ledger_error"] = str(exc)
    print(json.dumps(out, ensure_ascii=False))
    return 0


def _cmd_ls(args: argparse.Namespace) -> int:
    from . import targets

    rows = targets.listing()
    if args.json:
        print(json.dumps({"ok": True, "ledger": targets.ledger_path(), "targets": rows},
                         ensure_ascii=False, indent=2))
        return 0
    print("台账：%s" % targets.ledger_path())
    print("")
    for line in targets.render(rows):
        print(line)
    return 0


def _cmd_forget(args: argparse.Namespace) -> int:
    from . import targets

    ok = targets.forget(args.name)
    print(json.dumps({"ok": ok, "forgotten": args.name if ok else None,
                      "note": "只从台账里去掉，目录和里面的东西都没动"},
                     ensure_ascii=False))
    return 0 if ok else 1


def _cmd_probe(args: argparse.Namespace) -> int:
    ws = open_workspace(args.root)
    from .probe import ProbeRequest

    req = ProbeRequest(
        action_id=args.action_id,
        url=args.url,
        method=args.method,
        identity=args.identity,
        label=args.label,
        param_path=args.param,
        payload_class=args.payload,
        sample=args.sample,
        follow_redirects=args.follow,
        level=args.level,
        body_kind="json" if args.body_json else "none",
        body_json=json.loads(args.body_json) if args.body_json else None,
        id_plus_one=args.id_plus_one,
    )
    res = ws.probe.run(req)
    print(json.dumps(res.to_json(), ensure_ascii=False, indent=2))
    return 0 if res.status in ("ok", "pending_approval") else 1


def _cmd_replay(args: argparse.Namespace) -> int:
    ws = open_workspace(args.root)
    out = ws.replayer.replay(args.evidence_id)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("match") else 2


def _cmd_state(args: argparse.Namespace) -> int:
    ws = open_workspace(args.root)
    findings = [
        {
            "id": r["id"], "template": r["template_id"], "title": r["title"],
            "status": r["status"], "confidence": r["confidence"],
            "evidence_ids": json.loads(r["evidence_ids_json"]),
        }
        for r in ws.store.list_findings(ws.scope.engagement_id)
    ]
    ev = ws.store.list_evidence(ws.scope.engagement_id)
    print(json.dumps({
        "engagement": ws.scope.engagement_id,
        "budget": ws.budget.snapshot(),
        "evidence": len(ev),
        "findings": findings,
        "templates": [{"id": t.id, "level": t.level} for t in
                      [vhx.load(t) for t in vhx.TEMPLATES]],
    }, ensure_ascii=False, indent=2))
    return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    from .approvals import resolve_pending

    ws = open_workspace(args.root)
    row = resolve_pending(ws.store, ws.scope.engagement_id, args.fp)
    if row is None:
        print(json.dumps({"ok": False, "error": "approval 不存在，先用 probe 触发 pending_approval"},
                         ensure_ascii=False))
        return 1
    ws.gate.decide(
        engagement_id=row["engagement_id"], tool=row["tool"], host=row["host"],
        param_path=row["param_path"], payload_class=row["payload_class"], level=row["level"],
        decision=args.decision, scope=args.scope, note=args.note,
    )
    print(json.dumps({"ok": True, "fp": args.fp, "decision": args.decision,
                      "scope": args.scope}, ensure_ascii=False))
    return 0


def _cmd_grant(args: argparse.Namespace) -> int:
    """预授权：把"一类动作"提前批掉，而不是撞到 pending 再一条条点。"""
    from . import grants

    ws = open_workspace(args.root)
    try:
        specs, skipped = grants.expand(
            ws, template_ids=args.template or (), hosts=args.host or (),
            param_path=args.param, payload_class=args.payload, level=args.level)
    except grants.GrantError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    rows = grants.grant(ws, specs, ttl_hours=args.ttl, by=args.by,
                        note=args.note, dry_run=args.dry_run)
    if args.json:
        print(json.dumps({"ok": True, "dry_run": bool(args.dry_run),
                          "grants": rows, "skipped": skipped},
                         ensure_ascii=False, indent=2))
        return 0
    if args.dry_run:
        for line in grants.render_dry_run(rows, skipped):
            print(line)
        return 0
    print("已预授权 %d 条指纹，有效期 %g 小时：" % (len(rows), args.ttl))
    for r in rows:
        print("  %s  %-14s %-16s %-18s %s" % (
            r["fp"][:8], r["host"], r["param_path"] or "-",
            r["payload_class"] or "-", r["level"]))
    for s in skipped:
        print("  跳过 %s：%s" % (s["template_id"], s["reason"]))
    print("跑完用 `pta audit --root %s` 看实际放行了哪些发。" % args.root)
    return 0


def _cmd_grants(args: argparse.Namespace) -> int:
    from . import grants

    ws = open_workspace(args.root)
    rows = grants.listing(ws, level=args.level)
    if args.json:
        print(json.dumps({"ok": True, "grants": rows}, ensure_ascii=False, indent=2))
        return 0
    for line in grants.render_listing(rows):
        print(line)
    return 0


def _cmd_revoke(args: argparse.Namespace) -> int:
    from . import grants

    ws = open_workspace(args.root)
    if not args.fp and not args.level:
        print(json.dumps({"ok": False,
                          "error": "要么 --fp 指定一条，要么 --level 全撤"
                                   "（不写等于全部，容易误删）"}, ensure_ascii=False))
        return 1
    n = grants.revoke(ws, fp=args.fp, level=args.level)
    if args.json:
        print(json.dumps({"ok": True, "revoked": n}, ensure_ascii=False))
        return 0 if n else 1
    print("已撤销 %d 条" % n if n else "没有匹配的预授权")
    return 0 if n else 1


def _cmd_audit(args: argparse.Namespace) -> int:
    from . import grants

    ws = open_workspace(args.root)
    rows = grants.audit(ws, level=args.level, limit=args.limit)
    if args.json:
        print(json.dumps({"ok": True, "actions": rows,
                          "tally": dict(grants.tally(rows))},
                         ensure_ascii=False, indent=2))
        return 0
    for line in grants.render_audit(rows):
        print(line)
    return 0


def _cmd_logs(args: argparse.Namespace) -> int:
    ws = open_workspace(args.root)
    rows = ws.store.logs(ws.scope.engagement_id, args.decision)
    for r in rows:
        print("%s\t%s\t%s\t%s\t%s" % (r["ts"], r["decision"], r["tool"], r["host"], r["reason"]))
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    from .executor import Executor, Target
    from .oob import OobCollector

    oob = None
    if args.oob_host:
        oob = OobCollector(public_host=args.oob_host, bind_host="0.0.0.0",
                           http_port=args.oob_http_port, dns_port=args.oob_dns_port,
                           our_egress_ips=tuple(args.our_egress_ip or ())).start()
    ws = open_workspace(args.root, oob=oob)
    if getattr(args, "browser", False):
        from .workspace import attach_browser
        attach_browser(ws)
    by_id = {t["id"]: t for t in vhx.TEMPLATES}
    if args.template not in by_id:
        print(json.dumps({"ok": False, "error": "未知模板：%s" % args.template,
                          "available": sorted(by_id)}, ensure_ascii=False))
        return 1
    from . import overrides as ov

    frag: dict = {}
    if getattr(args, "no_overrides", False):
        tpl = vhx.load(by_id[args.template])
    else:
        # 走覆盖层：校准器给的阈值在这里生效，模板本身不动
        tpl, frag = ov.load_template(ws, args.template)
    target = Target(
        url=args.url,
        param_path=args.param,
        identity_baseline=args.identity_baseline,
        identity_probe=args.identity_probe,
        control_url=args.control_url,
        verify_url=args.verify_url,
        method=args.method,
        body_json=json.loads(args.body_json) if args.body_json else None,
        sample=args.sample,
        oob_wait_s=args.oob_wait,
        channel=getattr(args, "channel", None),
    )
    try:
        finding = Executor(ws.probe, ws.store, ws.scope.engagement_id,
                           browser=ws.browser).run(tpl, target)
    finally:
        from .workspace import close_browser
        close_browser(ws)
        if oob is not None:
            oob.stop()
    out = finding.to_json()
    if frag:
        out["overrides"] = {args.template: frag}
    # "baseline 给了身份、probe 没给"不是说错，是很多模板默认的对照方式（A vs 匿名）。
    # 但用户心里想的经常是"我只想验证登录态能不能读"，那样 probe 得跟 baseline 同一个身份，
    # 否则 probe 会是 302 跳登录页、结论看着像"没洞"。这里只说一句，不改任何默认值。
    if args.identity_baseline != "none" and args.identity_probe == "none":
        sys.stderr.write(
            "提示：probe 用的是匿名身份（没给 --identity-probe），所以这次对照是"
            "「%s vs 未登录」。只想验证登录态能读就补 --identity-probe %s。\n"
            % (args.identity_baseline, args.identity_baseline))
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def _model_from_args(args):
    if not (args.model_base_url and args.model_name):
        return None
    from .llm import OpenAICompatibleClient
    return OpenAICompatibleClient(args.model_base_url, args.model_api_key or "", args.model_name)


def _cmd_harvest(args: argparse.Namespace) -> int:
    """开一次浏览器，把页面自己发的接口调用收下来，并给出它意味着哪些候选。"""
    from .browser import NavRequest
    from .planner import Asset, heuristic_candidates, PlannerState
    from .workspace import attach_browser, close_browser, open_workspace

    ws = open_workspace(args.root)
    attach_browser(ws)
    if ws.browser is None:
        print(json.dumps({"ok": False, "error": "浏览器起不来（沙箱内需提权）"},
                         ensure_ascii=False))
        return 2
    try:
        res = ws.browser.navigate(NavRequest(
            url=args.url, identity=args.identity, harvest=True,
            harvest_limit=args.limit, settle_s=args.settle,
            wait_for=args.wait_for, screenshot=bool(args.screenshot)))
    finally:
        close_browser(ws)
    state = PlannerState.collect(ws)
    cands = [c.to_json() for c in heuristic_candidates(state)
             if any(c.url.split("?")[0] == (a.url or "").split("?")[0]
                    for a in state.assets)]
    print(json.dumps({
        "ok": res.status == "ok", "status": res.status, "reason": res.reason,
        "final_url": res.final_url, "evidence_id": res.evidence_id,
        "requests_allowed": res.requests_allowed, "denied": res.denied_urls,
        "harvested": res.harvested, "calls": res.harvest_calls,
        "candidates": cands[:10],
    }, ensure_ascii=False, indent=2))
    return 0 if res.status == "ok" else 1


def _cmd_plan(args: argparse.Namespace) -> int:
    from .planner import Planner

    ws = open_workspace(args.root)
    plan = Planner(ws, model=_model_from_args(args),
                   max_candidates=args.max_candidates).plan()
    print(json.dumps(plan.to_json(), ensure_ascii=False, indent=2))
    return 0


def _cmd_crawl(args: argparse.Namespace) -> int:
    from .recon import Recon, write_report

    ws = open_workspace(args.root)
    recon = Recon(ws, max_pages=args.max_pages, max_depth=args.max_depth,
                  identity=args.identity, parse_js=not args.no_js,
                  same_origin=not args.allow_cross_origin)
    report = recon.run(args.seed)
    path = write_report(ws, report)
    out = report.to_json()
    out["report_path"] = path
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def _cmd_discover(args: argparse.Namespace) -> int:
    from . import discover as disc

    ws = open_workspace(args.root)
    report = disc.discover(ws, args.seed or (), max_pages=args.max_pages,
                           max_depth=args.max_depth, identity=args.identity,
                           crawl=not args.no_crawl,
                           browser=args.browser, browser_limit=args.browser_limit,
                           browser_settle=args.browser_settle,
                           browser_wait_for=args.browser_wait_for,
                           graph_slots=args.graph_slots)
    if args.json:
        out = report.to_json()
        if args.write:
            out["report_path"] = disc.write_report(ws, report)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    path = disc.write_report(ws, report) if args.write else ""
    for line in disc.render(report, args.root):
        print(line)
    if path:
        print("")
        print("明细已写入：%s" % path)
    return 0


def _cmd_auto(args: argparse.Namespace) -> int:
    from .critic import Critic
    from .oob import OobCollector
    from .planner import EngagementRunner, Planner

    oob = None
    if args.oob_host:
        oob = OobCollector(public_host=args.oob_host, bind_host="0.0.0.0",
                           http_port=args.oob_http_port, dns_port=args.oob_dns_port).start()
    ws = open_workspace(args.root, oob=oob)
    if getattr(args, "browser", False):
        from .workspace import attach_browser
        attach_browser(ws)
    recon_out = None
    try:
        if getattr(args, "seed", None):
            from .recon import Recon, write_report
            recon_out = Recon(ws, max_pages=args.max_pages, max_depth=args.max_depth,
                              identity=args.identity).run(args.seed)
            write_report(ws, recon_out)
        planner = Planner(ws, model=_model_from_args(args),
                          max_candidates=args.max_candidates)
        summary = EngagementRunner(ws, planner, max_rounds=args.max_rounds,
                                   max_candidates=args.max_candidates,
                                   critic=Critic(ws),
                                   workers=getattr(args, "workers", 3),
                                   resume=getattr(args, "resume", False)).run()
        if recon_out is not None:      # 先侦察后验证：把侦察量也交给调用方
            summary["recon"] = recon_out.to_json()["counts"]
    finally:
        from .workspace import close_browser
        close_browser(ws)
        if oob is not None:
            oob.stop()
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


_NODE_CN = {"round": "轮", "asset": "资产", "candidate": "候选"}


def _cmd_tree(args: argparse.Namespace) -> int:
    """把 PTT 打成一棵树。节点是"当前事实"（INSERT OR REPLACE），不是流水账。"""
    ws = open_workspace(args.root)
    eng = ws.scope.engagement_id
    rows = ws.store.nodes(eng)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    by_parent: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_parent.setdefault(r.get("parent_id") or "", []).append(r)
    if not rows:
        print("（还没有任务节点：先跑 auto 或 plan）")
        return 0

    def walk(parent: str, depth: int) -> None:
        for r in by_parent.get(parent, []):
            detail = json.loads(r.get("detail_json") or "{}")
            note = ""
            if detail:
                note = "  " + " ".join("%s=%s" % (k, detail[k]) for k in
                                       ("confidence", "requests", "stop_reason") if k in detail)
            print("%s%s [%s]%s" % ("  " * depth, r["label"], r["status"], note))
            walk(r["node_id"], depth + 1)

    walk("", 0)
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["status"].split(":")[0]] = counts.get(r["status"].split(":")[0], 0) + 1
    print("\n共 %d 个节点：%s" % (len(rows), ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    return 0


def _cmd_calibrate(args: argparse.Namespace) -> int:
    """先量噪声再下阈值：把默认 1800ms/0.15 换成本目标实测出来的值。

    `--apply` 把建议写进工作区的 overrides.json（不是改模板本身）：
    模板是资产，一份模板要服务很多目标，把某次测量的结果写死进去，
    下一次演练就会继承上一次的假设。
    """
    from . import overrides as ov
    from .calibrate import Calibrator, write_calibration

    ws = open_workspace(args.root)
    cal = Calibrator(ws, args.url, param_path=args.param, samples=args.samples,
                     identity=args.identity, method=args.method).run()
    out = cal.to_json()
    path = write_calibration(ws, cal, name=args.out or "calibration.json")
    out["path"] = path
    if args.apply:
        tid = args.template or "sqli-time-blind"
        frag = ov.from_suggestion(cal.suggestion)
        if not frag:
            out["applied"] = {}
            out["apply_note"] = "这次没有可用的建议（%s），overrides 未改动" % cal.verdict
        else:
            data = ov.read(ws)
            data[tid] = frag
            out["overrides_path"] = ov.write(ws, data)
            out["applied"] = {tid: frag}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if cal.verdict in ("ok", "noisy") else 1


def _cmd_overrides(args: argparse.Namespace) -> int:
    """看/清工作区的覆盖层：哪些阈值被校准结果改过。"""
    from . import overrides as ov

    ws = open_workspace(args.root)
    if args.clear:
        removed = ov.clear(ws)
        print(json.dumps({"ok": True, "cleared": removed,
                          "path": ov.path_for(ws)}, ensure_ascii=False))
        return 0
    data = ov.read(ws)
    if args.json:
        print(json.dumps({"templates": data, "path": ov.path_for(ws)},
                         ensure_ascii=False, indent=2))
        return 0
    lines = ov.describe(data)
    if not lines:
        print("没有覆盖（模板用的是内置默认值）：%s" % ov.path_for(ws))
        return 0
    print("覆盖层：%s" % ov.path_for(ws))
    for line in lines:
        print("  " + line)
    return 0


def _cmd_critic(args: argparse.Namespace) -> int:
    from .critic import Critic

    ws = open_workspace(args.root)
    out = Critic(ws, model=_model_from_args(args)).review_all(apply=not args.dry_run)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def _cmd_oob(args: argparse.Namespace) -> int:
    """只跑收集器：起 HTTP+DNS，打印回连。用于手工验证/真实演练。"""
    import time

    from .oob import OobCollector

    oob = OobCollector(public_host=args.public_host, bind_host="0.0.0.0",
                       http_port=args.http_port, dns_port=args.dns_port,
                       our_egress_ips=tuple(args.our_egress_ip or ())).start()
    token = oob.arm("manual", note="cli oob", token=args.token)
    print(json.dumps({
        "ok": True, "token": token,
        "http_url": oob.url_for(token), "dns_host": oob.host_for(token),
        "http_port": oob.http_port, "dns_port": oob.dns_port,
    }, ensure_ascii=False))
    deadline = time.time() + args.seconds if args.seconds > 0 else None
    seen = 0
    try:
        while deadline is None or time.time() < deadline:
            calls = oob.check(token)
            if len(calls) > seen:
                for cb in calls[seen:]:
                    print("回连 %s %s %s <- %s" % (cb.ts, cb.protocol, cb.path, cb.source_ip))
                seen = len(calls)
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        oob.stop()
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from .report import ReportOptions, export_report

    ws = open_workspace(args.root)
    eng = tuple(args.engagement or ())
    if getattr(args, "all", False):
        # 合并模式要显式把库里每一轮都列出来：静默"全导"会把无关演练也卷进来
        eng = tuple(r["id"] for r in ws.store.list_engagements())
    opts = ReportOptions(
        statuses=tuple(args.only) if args.only else ("confirmed", "hypothesis", "refuted"),
        include_bodies=not args.no_bodies,
        redact=not args.no_redact,
        max_body_bytes=args.max_body_bytes,
        extra_secrets=tuple(args.secret or ()),
        include_recon=not args.no_recon,
        include_all_evidence=args.all_evidence,
        html=getattr(args, "html", False),
        engagements=eng,
    )
    m = export_report(ws, args.out, opts)
    print(json.dumps({"ok": not m["verify"]["mismatches"] and m["verify"]["manifest_chain"],
                      "out_dir": m["out_dir"], "root_sha256": m["root_sha256"],
                      "counts": m["counts"], "verify": m["verify"]},
                     ensure_ascii=False, indent=2))
    return 0 if not m["verify"]["mismatches"] and m["verify"]["manifest_chain"] else 3


def _cmd_verify(args: argparse.Namespace) -> int:
    ws = open_workspace(args.root)
    ok = ws.cas.manifest.verify()
    print(json.dumps({"manifest_chain": "ok" if ok else "broken"}, ensure_ascii=False))
    return 0 if ok else 3


def _cmd_show(args: argparse.Namespace) -> int:
    """把一条结论还原成能直接复制去打的请求。

    默认打人类可读的说明 + 命令（这段是要粘到别处去的，不能是 JSON 大括号），
    要机器读加 --json。
    """
    from . import poc as poc_mod

    ws = open_workspace(args.root)
    poc = poc_mod.load(ws, args.finding, last=bool(args.last))

    body_path = None
    if poc.body and (args.body_out or poc.binary_body):
        target = args.body_out or os.path.join(
            os.path.abspath(args.root), "poc_%s.body" % (poc.finding_id[:12] or "body"))
        body_path = poc_mod.save_body(poc, target)

    text = poc_mod.render(poc, args.as_format, body_path=body_path)

    if args.json:
        print(json.dumps({
            "ok": True, "finding_id": poc.finding_id, "template_id": poc.template_id,
            "title": poc.title, "status": poc.status, "confidence": poc.confidence,
            "evidence_id": poc.evidence_id, "role": poc.role,
            "method": poc.method, "url": poc.url,
            "headers": [name for name, _ in poc.headers],
            "body_len": len(poc.body), "body_file": body_path,
            "response": {"status": poc.response_status, "content_type": poc.response_type,
                         "body_len": poc.response_len},
            "metrics": poc.metrics, "rationale": poc.rationale,
            "warnings": poc.warnings, "format": args.as_format, "poc": text,
        }, ensure_ascii=False, indent=2))
        return 0

    for line in poc_mod.explain(poc):
        print(line)
    print("")
    print("--- 复制下面这段去打 ---")
    print(text)
    print("--- 结束 ---")
    if body_path:
        print("请求体已写到：%s" % body_path)
    if any(v for _, v in poc.headers):
        print("提示：这段里有明文凭证，别粘进聊天工具；打完记得清 shell 历史。")
    return 0


# ---------- 人工标注 ----------

def _cmd_mark(args: argparse.Namespace) -> int:
    """标一条结论是误报还是真洞。改的是口径，不是证据。"""
    from . import labels as labels_mod

    ws = open_workspace(args.root)
    label = "fp" if args.fp else ("tp" if args.tp else "fp")
    if not (args.fp or args.tp) and not args.clear:
        print(json.dumps({"ok": False, "error": "要么 --fp（其实是误报），要么 --tp（确实是洞）"},
                         ensure_ascii=False))
        return 1
    res = labels_mod.mark(ws, args.finding, last=bool(args.last), label=label,
                          note=args.note or "", by=args.by or "", clear=bool(args.clear))

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if res.get("cleared"):
        print("已撤销标注：%s 恢复成 %s（系统原判 %s）"
              % (res["finding_id"], res["status"], res["original_status"]))
        return 0

    word = "误报" if res["label"] == "fp" else "确认"
    print("已标为%s：%s  %s" % (word, res["template_id"], res["finding_id"]))
    if res["original_status"] == res["status"]:
        print("  状态：%s（没变，这条记下的是「人确认过」，不是改判）" % res["status"])
    else:
        print("  状态：%s → %s（系统当时的置信度 %.2f 保留在 verdict 里，没有抹掉）"
              % (res["original_status"], res["status"], res["confidence"]))
    if res["note"]:
        print("  备注：%s" % res["note"])
    if res["replayable"]:
        print("  重放坐标已存：%s %s" % (res["target"].get("method", "GET"),
                                        res["target"].get("url", "")))
    else:
        print("  没有可重放的坐标（证据缺失或只到 pending）：这条只能当统计样本")
    print("  看整体：python -m pta.cli stats --root %s" % args.root)
    return 0


def _cmd_labels(args: argparse.Namespace) -> int:
    from . import labels as labels_mod

    ws = open_workspace(args.root)
    rows = labels_mod.listing(ws, args.label)
    if args.json:
        print(json.dumps({"ok": True, "labels": rows}, ensure_ascii=False, indent=2))
        return 0
    if not rows:
        print("还没有任何标注。判错的结论上跑一次 `pta mark --last --fp --note \"...\"`。")
        return 0
    print("%-20s %-6s %-26s %-22s %s" % ("模板", "标注", "finding", "时间(UTC)", "备注"))
    for r in rows:
        print("%-20s %-6s %-26s %-22s %s"
              % (r["template_id"], "误报" if r["label"] == "fp" else "确认",
                 r["finding_id"][:24], r["at"][:19], r["note"][:40]))
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    from . import labels as labels_mod

    ws = open_workspace(args.root)
    rows = labels_mod.stats(ws)
    if args.json:
        print(json.dumps({"ok": True, "stats": rows}, ensure_ascii=False, indent=2))
        return 0
    if not rows:
        print("工作区里还没有结论。")
        return 0
    print("%-22s %6s %10s %11s %8s %6s %5s %8s"
          % ("模板", "结论", "系统confirmed", "hypothesis", "refuted", "误报", "确认", "误报率"))
    for r in rows:
        rate = "—" if r["fp_rate"] is None else "%.0f%%" % (r["fp_rate"] * 100)
        print("%-22s %6d %10d %11d %8d %6d %5d %8s"
              % (r["template_id"], r["findings"], r["confirmed"], r["hypothesis"],
                 r["refuted"], r["fp"], r["tp"], rate))
    marked = sum(r["fp"] + r["tp"] for r in rows)
    if marked == 0:
        print("")
        print("一条都还没标过：误报率这一列是「—」而不是 0%——没看过的东西不能算准。")
    return 0


# ---------- 身份凭证 ----------

def _load_imported(args: argparse.Namespace):
    groups = []
    extra_drop = tuple(args.drop or ())
    if args.from_curl:
        text = credentials.read_text(args.from_curl)
        imported = credentials.parse_curl(text, drop_extra=extra_drop,
                                          keep_all=bool(args.all))
        groups.append(imported.headers)
    if args.cookie_file:
        jar = credentials.parse_cookie_file(credentials.read_text(args.cookie_file))
        if jar:
            groups.append((("Cookie", jar),))
    if args.header:
        groups.append(credentials.parse_header_lines(args.header, keep_all=True))
    return credentials.merge_headers(*groups)


def _cmd_auth_add(args: argparse.Namespace) -> int:
    ident = credentials.check_identity(args.identity)
    headers = _load_imported(args)
    if not headers:
        print(json.dumps({"ok": False, "error": "没解析出任何身份头；检查 --from-curl / --header"},
                         ensure_ascii=False))
        return 1
    ws = open_workspace(args.root)
    for name, value in headers:
        ws.vault.put("cred/%s/%s" % (ident, name.lower()), value)
    print(json.dumps({
        "ok": True,
        "identity": ident,
        "saved": [{"name": n, "value": credentials.mask(v)} for n, v in headers],
        "hint": "现在可以用 --identity %s 跑模板；值只在请求里出现，日志存的是哈希" % ident,
    }, ensure_ascii=False, indent=2))
    return 0


def _cmd_auth_ls(args: argparse.Namespace) -> int:
    ws = open_workspace(args.root)
    out = []
    for ident in ws.vault.identities():
        heads = []
        for ref, val in ws.vault.items("cred/%s/" % ident).items():
            heads.append({"name": ref.rsplit("/", 1)[-1], "value": credentials.mask(val)})
        out.append({"identity": ident, "headers": heads})
    print(json.dumps({"ok": True, "identities": out}, ensure_ascii=False, indent=2))
    return 0


def _cmd_auth_rm(args: argparse.Namespace) -> int:
    ident = credentials.check_identity(args.identity)
    ws = open_workspace(args.root)
    removed = []
    if args.header:
        for name in args.header:
            if ws.vault.delete("cred/%s/%s" % (ident, name.lower())):
                removed.append(name.lower())
    else:
        for ref in ws.vault.items("cred/%s/" % ident):
            if ws.vault.delete(ref):
                removed.append(ref.rsplit("/", 1)[-1])
    print(json.dumps({"ok": bool(removed), "identity": ident, "removed": removed},
                     ensure_ascii=False))
    return 0 if removed else 1


def _cmd_auth_check(args: argparse.Namespace) -> int:
    """用工作区里的身份发一发，看它到底还登不登着。"""
    from .probe import ProbeRequest

    ident = credentials.check_identity(args.identity)
    ws = open_workspace(args.root)
    if not ws.vault.items("cred/%s/" % ident):
        print(json.dumps({"ok": False, "error": "这个身份没有任何凭证：%s" % ident},
                         ensure_ascii=False))
        return 2
    res = ws.probe.run(ProbeRequest(action_id="auth:check", url=args.url, method="GET",
                                    identity=ident, label="auth", level="L1"))
    if res.status != "ok" or res.extract is None:
        print(json.dumps({"ok": False, "status": res.status, "reason": res.reason},
                         ensure_ascii=False))
        return 1
    body = ""
    ev = res.extract
    if getattr(ev, "body_sha256", None):
        raw = ws.cas.get(ev.body_sha256) or b""
        body = raw[:65536].decode("utf-8", "replace").lower()
    looks_login = ("type=\"password\"" in body or "type='password'" in body
                   or ("login" in body and "logout" not in body))
    out = {
        "ok": True,
        "identity": ident,
        "url": ev.url,
        "status": ev.status,
        "content_type": ev.content_type,
        "looks_like_login_page": bool(looks_login or ev.status in (401, 403)),
        "evidence_id": ev.evidence_id,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pta", description="PTA P0")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init")
    i.add_argument("--root", required=True)
    i.add_argument("--engagement", required=True)
    i.add_argument("--domain", action="append", required=True)
    i.add_argument("--allow-private", action="store_true")
    i.add_argument("--allow-port", action="append", type=int, default=None,
                   help="额外放行端口（本地靶场用，默认仅 80/443）")
    i.add_argument("--egress-proxy", default=None)
    i.add_argument("--rate", type=float, default=5.0)
    i.add_argument("--max-requests", type=int, default=9000)
    i.add_argument("--expires-at", default=None)
    i.add_argument("--alias", default=None, help="台账里的短名，之后可直接当 --root 用")
    i.add_argument("--note", default=None, help="给自己看的备注（装的是什么目标）")
    i.add_argument("--no-register", action="store_true", help="不登记进目标台账")
    i.set_defaults(fn=_cmd_init, literal_root=True)

    ls = sub.add_parser("ls", help="列出登记过的目标（别名/域/结论数/最后活动）")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(fn=_cmd_ls)

    fg = sub.add_parser("forget", help="从台账里去掉一个目标（不删目录）")
    fg.add_argument("name", help="别名或工作区路径")
    fg.set_defaults(fn=_cmd_forget)

    pr = sub.add_parser("probe")
    pr.add_argument("--root", required=True)
    pr.add_argument("--url", required=True)
    pr.add_argument("--method", default="GET")
    pr.add_argument("--identity", default="none")
    pr.add_argument("--label", default="single")
    pr.add_argument("--param", default=None)
    pr.add_argument("--payload", default=None)
    pr.add_argument("--sample", type=int, default=1)
    pr.add_argument("--follow", action="store_true")
    pr.add_argument("--level", default=None)
    pr.add_argument("--body-json", default=None)
    pr.add_argument("--id-plus-one", default=None)
    pr.add_argument("--action-id", default="")
    pr.set_defaults(fn=_cmd_probe)

    rp = sub.add_parser("replay")
    rp.add_argument("--root", required=True)
    rp.add_argument("--evidence-id", required=True)
    rp.set_defaults(fn=_cmd_replay)

    st = sub.add_parser("state")
    st.add_argument("--root", required=True)
    st.set_defaults(fn=_cmd_state)

    rn = sub.add_parser("run")
    rn.add_argument("--root", required=True)
    rn.add_argument("--template", required=True)
    rn.add_argument("--url", required=True)
    rn.add_argument("--param", default=None)
    rn.add_argument("--identity-baseline", default="none")
    rn.add_argument("--identity-probe", default="none")
    rn.add_argument("--control-url", default=None,
                    help="同一主机上已知需要授权的接口，用来取拒绝模板（authz-missing-endpoint 用）")
    rn.add_argument("--method", default="GET")
    rn.add_argument("--body-json", default=None)
    rn.add_argument("--verify-url", default=None,
                    help="写后回读的地址（存储型 XSS / 业务逻辑边界需要；"
                         "不给就回落到发送地址）")
    rn.add_argument("--sample", type=int, default=1)
    rn.add_argument("--oob-host", default=None, help="跑 OOB 模板时绑定的收集器对外域名")
    rn.add_argument("--oob-http-port", type=int, default=0)
    rn.add_argument("--oob-dns-port", type=int, default=0)
    rn.add_argument("--oob-wait", type=float, default=3.0)
    rn.add_argument("--channel", choices=("plain", "browser", "curl"), default=None,
                    help="起始客户端身份；被拦时引擎会自动换档，这里只决定第一发用哪档")
    rn.add_argument("--browser", action="store_true",
                    help="起真浏览器（browser_nav 模板需要；沙箱内需提权）")
    rn.add_argument("--no-overrides", action="store_true",
                    help="忽略工作区 overrides.json，用模板内置阈值（复核校准是否真起作用时用）")
    rn.set_defaults(fn=_cmd_run)

    hv = sub.add_parser("harvest", help="开浏览器采页面自己发的接口（不判漏洞，只记字段）")
    hv.add_argument("--root", required=True)
    hv.add_argument("--url", required=True)
    hv.add_argument("--identity", default="none")
    hv.add_argument("--limit", type=int, default=12, help="最多记几条（按形状去重后）")
    hv.add_argument("--settle", type=float, default=2.0, help="等页面发完请求的秒数")
    hv.add_argument("--wait-for", default=None, help="额外的 JS 条件，为真即视为加载完成")
    hv.add_argument("--screenshot", action="store_true")
    hv.set_defaults(fn=_cmd_harvest)

    pl = sub.add_parser("plan")
    pl.add_argument("--root", required=True)
    pl.add_argument("--max-candidates", type=int, default=5)
    pl.add_argument("--model-base-url", default=None, help="OpenAI 兼容端点，如 http://127.0.0.1:8000/v1")
    pl.add_argument("--model-api-key", default=None)
    pl.add_argument("--model-name", default=None)
    pl.set_defaults(fn=_cmd_plan)

    crw = sub.add_parser("crawl", help="从一个种子 URL 铺开资产表（只发 L1 GET）")
    crw.add_argument("--root", required=True)
    crw.add_argument("--seed", action="append", required=True, help="可重复；每个是起点 URL")
    crw.add_argument("--max-pages", type=int, default=25)
    crw.add_argument("--max-depth", type=int, default=2)
    crw.add_argument("--identity", default="none", help="带哪个身份抓（vault 里的 cred/<id>/authorization）")
    crw.add_argument("--no-js", action="store_true", help="不解析 JS 里的接口路径")
    crw.add_argument("--allow-cross-origin", action="store_true",
                     help="允许抓其它域名的链接（默认只抓种子所在主机）")
    crw.set_defaults(fn=_cmd_crawl)

    dsc = sub.add_parser("discover",
                         help="从种子爬一遍，出「能直接跑的候选」和「为什么没候选」")
    dsc.add_argument("--root", required=True)
    dsc.add_argument("--seed", action="append", default=None,
                     help="可重复；--no-crawl 时可以不给")
    dsc.add_argument("--max-pages", type=int, default=25)
    dsc.add_argument("--max-depth", type=int, default=2)
    dsc.add_argument("--identity", default="none", help="带哪个身份抓")
    dsc.add_argument("--no-crawl", action="store_true",
                     help="不爬，只读工作区里已有的证据（省请求）")
    dsc.add_argument("--browser", action="store_true",
                     help="另开一次真浏览器，把页面自己发的接口也算成资产（SPA 必备）")
    dsc.add_argument("--browser-limit", type=int, default=60,
                     help="浏览器最多记多少条请求")
    dsc.add_argument("--browser-settle", type=float, default=2.0,
                     help="页面静下来后再等几秒（懒加载接口）")
    dsc.add_argument("--browser-wait-for", default=None,
                     help="等到这个 CSS 选择器出现（登录后的首页）")
    dsc.add_argument("--graph-slots", type=int, default=4,
                     help="资产图外推最多占几个候选位子（0 = 不保留，纯按优先级排）")
    dsc.add_argument("--json", action="store_true")
    dsc.add_argument("--write", action="store_true", help="明细写进 discover.json")
    dsc.set_defaults(fn=_cmd_discover)

    au = sub.add_parser("auto")
    au.add_argument("--root", required=True)
    au.add_argument("--seed", action="append", default=None,
                    help="先侦察这些 URL，再做 auto（可重复）")
    au.add_argument("--max-pages", type=int, default=25)
    au.add_argument("--max-depth", type=int, default=2)
    au.add_argument("--identity", default="none")
    au.add_argument("--max-rounds", type=int, default=3)
    au.add_argument("--max-candidates", type=int, default=5)
    au.add_argument("--workers", type=int, default=3,
                    help="并发验证的候选数（默认 3；预算与审批暂停仍按批检查）")
    au.add_argument("--model-base-url", default=None)
    au.add_argument("--model-api-key", default=None)
    au.add_argument("--model-name", default=None)
    au.add_argument("--oob-host", default=None)
    au.add_argument("--oob-http-port", type=int, default=0)
    au.add_argument("--oob-dns-port", type=int, default=0)
    au.add_argument("--browser", action="store_true")
    au.add_argument("--resume", action="store_true",
                    help="从 PTT 断点续跑：已有结论的候选不再发包，预算按账本接上")
    au.set_defaults(fn=_cmd_auto)

    cb = sub.add_parser("calibrate", help="量目标的时间噪声，给出时间判定的阈值建议")
    cb.add_argument("--root", required=True)
    cb.add_argument("--url", required=True, help="要量的那个正常请求（不带载荷）")
    cb.add_argument("--param", default=None, help="query:name / body:*，留空表示路径型")
    cb.add_argument("--samples", type=int, default=30)
    cb.add_argument("--identity", default="none")
    cb.add_argument("--method", default="GET")
    cb.add_argument("--out", default=None, help="写到工作区里的文件名（默认 calibration.json）")
    cb.add_argument("--apply", action="store_true",
                    help="把建议写进工作区 overrides.json（只调阈值，不改判定）")
    cb.add_argument("--template", default=None,
                    help="配合 --apply：覆盖哪个模板（默认 sqli-time-blind）")
    cb.set_defaults(fn=_cmd_calibrate)

    ovp = sub.add_parser("overrides", help="查看/清除工作区的模板覆盖层")
    ovp.add_argument("--root", required=True)
    ovp.add_argument("--clear", action="store_true")
    ovp.add_argument("--json", action="store_true")
    ovp.set_defaults(fn=_cmd_overrides)

    ah = sub.add_parser("auth", help="身份凭证：从浏览器 curl 导入 / 查看 / 删除 / 试一发")
    ahsub = ah.add_subparsers(dest="auth_cmd", required=True)

    aa = ahsub.add_parser("add", help="导入一个身份的请求头（复制 devtools 的 Copy as cURL 粘进来）")
    aa.add_argument("--root", required=True)
    aa.add_argument("--identity", required=True)
    aa.add_argument("--from-curl", default=None,
                    help="cURL 文本文件；`-` 表示从 stdin 读（直接粘贴）")
    aa.add_argument("--header", action="append", default=None,
                    help="手工补一条头，可重复：--header \"X-CSRF-Token: abc\"")
    aa.add_argument("--cookie-file", default=None,
                    help="cookies.txt（Netscape 7 列）或 `k=v; k2=v2` 文本")
    aa.add_argument("--drop", action="append", default=None, help="额外丢弃某个头（可重复）")
    aa.add_argument("--all", action="store_true",
                    help="不过滤，原样保存所有头（UA / Sec-Fetch-* 会和通道消歧打架）")
    aa.set_defaults(fn=_cmd_auth_add)

    al = ahsub.add_parser("ls", help="列出工作区里的身份（值只显示掩码）")
    al.add_argument("--root", required=True)
    al.set_defaults(fn=_cmd_auth_ls)

    ar = ahsub.add_parser("rm", help="删掉一个身份（或它的某几条头）")
    ar.add_argument("--root", required=True)
    ar.add_argument("--identity", required=True)
    ar.add_argument("--header", action="append", default=None)
    ar.set_defaults(fn=_cmd_auth_rm)

    ac = ahsub.add_parser("check", help="用这个身份发一发 GET，看还登不登着")
    ac.add_argument("--root", required=True)
    ac.add_argument("--identity", required=True)
    ac.add_argument("--url", required=True)
    ac.set_defaults(fn=_cmd_auth_check)

    tr = sub.add_parser("tree", help="打印任务树（PTT）")
    tr.add_argument("--root", required=True)
    tr.add_argument("--json", action="store_true", help="输出原始节点 JSON")
    tr.set_defaults(fn=_cmd_tree)

    cr = sub.add_parser("critic")
    cr.add_argument("--root", required=True)
    cr.add_argument("--dry-run", action="store_true", help="只出复核结论，不改 finding 状态")
    cr.add_argument("--model-base-url", default=None)
    cr.add_argument("--model-api-key", default=None)
    cr.add_argument("--model-name", default=None)
    cr.set_defaults(fn=_cmd_critic)

    ol = sub.add_parser("oob")
    ol.add_argument("--public-host", default="127.0.0.1")
    ol.add_argument("--http-port", type=int, default=8000)
    ol.add_argument("--dns-port", type=int, default=5353)
    ol.add_argument("--token", default=None, help="预置一个 token 便于手工测试")
    ol.add_argument("--our-egress-ip", action="append", default=None,
                    help="我方出口 IP，命中即视为自触发")
    ol.add_argument("--seconds", type=float, default=0, help="0 = 一直跑")
    ol.set_defaults(fn=_cmd_oob)

    ap = sub.add_parser("approve")
    ap.add_argument("--root", required=True)
    ap.add_argument("--fp", required=True)
    ap.add_argument("--decision", default="approve", choices=["approve", "reject", "modify"])
    ap.add_argument("--scope", default="once", choices=["once", "class"])
    ap.add_argument("--note", default="")
    ap.set_defaults(fn=_cmd_approve)

    gr = sub.add_parser("grant", help="预授权：跑之前把一类动作批掉（默认 24h）")
    gr.add_argument("--root", required=True)
    gr.add_argument("--template", action="append", default=None,
                    help="按模板展开要批的指纹（可重复）")
    gr.add_argument("--host", action="append", default=None,
                    help="主机；默认用 scope.domains")
    gr.add_argument("--param", default=None, help="参数路径，如 body:amount")
    gr.add_argument("--payload", default=None, help="载荷类，如 negative_number")
    gr.add_argument("--level", default="L2", choices=["L2", "L3"])
    gr.add_argument("--ttl", type=float, default=24.0, help="有效期小时数")
    gr.add_argument("--by", default="", help="批给人（进审计表）")
    gr.add_argument("--note", default="")
    gr.add_argument("--dry-run", action="store_true", help="只打印展开结果，不写入")
    gr.add_argument("--json", action="store_true")
    gr.set_defaults(fn=_cmd_grant)

    gs = sub.add_parser("grants", help="列出生效中的预授权")
    gs.add_argument("--root", required=True)
    gs.add_argument("--level", default=None, choices=["L2", "L3"])
    gs.add_argument("--json", action="store_true")
    gs.set_defaults(fn=_cmd_grants)

    rv = sub.add_parser("revoke", help="撤销预授权（不给 --fp 就按等级全撤）")
    rv.add_argument("--root", required=True)
    rv.add_argument("--fp", default=None)
    rv.add_argument("--level", default=None, choices=["L2", "L3"])
    rv.add_argument("--json", action="store_true")
    rv.set_defaults(fn=_cmd_revoke)

    au = sub.add_parser("audit", help="看 L2+ 的动作是凭什么放行的")
    au.add_argument("--root", required=True)
    au.add_argument("--level", default="L2", choices=["L1", "L2", "L3"])
    au.add_argument("--limit", type=int, default=200)
    au.add_argument("--json", action="store_true")
    au.set_defaults(fn=_cmd_audit)

    lg = sub.add_parser("logs")
    lg.add_argument("--root", required=True)
    lg.add_argument("--decision", default=None)
    lg.set_defaults(fn=_cmd_logs)

    vf = sub.add_parser("verify")
    vf.add_argument("--root", required=True)
    vf.set_defaults(fn=_cmd_verify)

    sh = sub.add_parser("show", help="把一条结论还原成能直接复制去打的请求（PoC）")
    sh.add_argument("--root", required=True)
    sh.add_argument("finding", nargs="?", default=None, help="结论 id；不给就配 --last")
    sh.add_argument("--last", action="store_true", help="用工作区里最近一条结论")
    sh.add_argument("--as", dest="as_format", default="curl",
                    choices=["curl", "powershell", "raw", "python"],
                    help="渲染成什么（默认 curl，bash 风格；Windows 用 powershell）")
    sh.add_argument("--body-out", default=None,
                    help="把请求体写成文件（二进制体会自动写；curl 里用 @该文件）")
    sh.add_argument("--json", action="store_true", help="输出结构化 JSON（含 poc 字段）")
    sh.set_defaults(fn=_cmd_show)

    mk = sub.add_parser("mark", help="标一条结论是误报还是真洞（改口径不改证据）")
    mk.add_argument("--root", required=True)
    mk.add_argument("finding", nargs="?", default=None, help="结论 id；不给就配 --last")
    mk.add_argument("--last", action="store_true", help="标最新那条")
    mk.add_argument("--fp", action="store_true", help="其实是误报（status → refuted）")
    mk.add_argument("--tp", action="store_true", help="确实是洞（status → confirmed）")
    mk.add_argument("--clear", action="store_true", help="撤销标注，恢复系统原判")
    mk.add_argument("--note", default="", help="为什么判错（写给人看，也是以后训规则的材料）")
    mk.add_argument("--by", default="", help="标注人（多人共用工作区时用）")
    mk.add_argument("--json", action="store_true")
    mk.set_defaults(fn=_cmd_mark)

    lb = sub.add_parser("labels", help="列出人工标注")
    lb.add_argument("--root", required=True)
    lb.add_argument("--label", default=None, choices=["fp", "tp"],
                    help="只看误报 / 只看确认")
    lb.add_argument("--json", action="store_true")
    lb.set_defaults(fn=_cmd_labels)

    stt = sub.add_parser("stats", help="按模板看结论分布与误报率")
    stt.add_argument("--root", required=True)
    stt.add_argument("--json", action="store_true")
    stt.set_defaults(fn=_cmd_stats)

    rp = sub.add_parser("report", help="导出可离线复核的报告包（结论 + 证据原文 + 整包指纹）")
    rp.add_argument("--root", required=True)
    rp.add_argument("--out", required=True, help="输出目录（不存在会创建；同名文件会被覆盖）")
    rp.add_argument("--only", action="append", default=None,
                    choices=["confirmed", "hypothesis", "refuted"],
                    help="只导这些状态，可重复；默认三条全导")
    rp.add_argument("--no-bodies", action="store_true", help="不导响应正文，只导请求与元数据")
    rp.add_argument("--no-redact", action="store_true",
                    help="不脱敏（只在确认正文无凭据时用；包会原样带出去）")
    rp.add_argument("--max-body-bytes", type=int, default=512 * 1024)
    rp.add_argument("--secret", action="append", default=None,
                    help="额外替换掉的敏感串，可重复")
    rp.add_argument("--no-recon", action="store_true", help="不附带工作区里的 recon.json")
    rp.add_argument("--all-evidence", action="store_true",
                    help="连没挂结论的证据（侦察页/基线）一起导出")
    rp.add_argument("--html", action="store_true",
                    help="同时导出单文件 report.html（内联样式、无外部资源，双击就能看）")
    rp.add_argument("--engagement", action="append", default=None,
                    help="只导这些 engagement，可重复；默认只导当前工作区那一轮")
    rp.add_argument("--all", action="store_true",
                    help="把库里所有 engagement 合并进同一份报告（每条结论会标注所属轮次）")
    rp.set_defaults(fn=_cmd_report)

    ui = sub.add_parser("ui", help="开操作台：项目列表 / 新建 / 详情（不加 --workspace 就是多项目）")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--workspace", default="",
                    help="只绑一个工作区（老用法；不给就是整个台账）")
    ui.set_defaults(fn=_cmd_ui)
    return p


def _resolve_root_alias(args: argparse.Namespace) -> None:
    """把 `--root lab2` 这种台账别名换成真实路径。

    两条例外：
    - `init` 按字面路径建（否则 `init --root lab2` 会往旧工作区里写）；
    - 别名解析不出来就原样留着，让下游按普通路径处理（可能是想新建的目录）。
    """
    if getattr(args, "literal_root", False):
        return
    root = getattr(args, "root", None)
    if not root or os.path.isdir(root):
        return
    from . import targets

    try:
        real = targets.resolve(root)
    except targets.LedgerError:
        return
    if real:
        args.root = real


def _cmd_ui(args) -> int:
    """开操作台。两个模式共用同一个前端：给了 --workspace 就只绑那一个，否则认整个台账。"""
    from . import projects as proj
    from . import targets
    from .api import serve
    from .projects import ProjectBook
    from .workspace import open_workspace

    if args.workspace:
        ws = open_workspace(args.workspace)
        # 显式点名了一个工作区，就顺手让台账也认它——否则列表页/交付在单工作区模式下
        # 会找不到这行（早期的 pta init 不写台账）。已经在台账里就什么都不做。
        if targets.get(ws.root) is None:
            try:
                proj.adopt(ws.root, name=os.path.basename(os.path.abspath(ws.root)))
            except proj.ProjectError as exc:
                print(json.dumps({"ok": False, "warning": "没登记进台账：%s" % exc.message},
                                 ensure_ascii=False))
        book = ProjectBook.single(ws)
    else:
        book = ProjectBook()
    serve(book, host=args.host, port=args.port)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _resolve_root_alias(args)
    try:
        return args.fn(args)
    except credentials.CredentialError as exc:
        # 粘贴的东西不对是常态（复制到了半条 curl、忘了带 scheme），说清楚就行，
        # 不该甩一坨 traceback 让人以为是工具坏了。
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    except KeyError as exc:
        print(json.dumps({"ok": False, "error": "缺少凭证：%s" % exc}, ensure_ascii=False))
        return 1
    except PocError as exc:
        # 「这条结论没证据/证据对不上」是使用路径上的常见错，不是崩溃。
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    except labels.LabelError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    except grants.GrantError as exc:
        # "只写放行 L2"这类用法错误要说清楚，而不是当崩溃
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
