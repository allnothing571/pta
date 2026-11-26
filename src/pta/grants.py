"""预授权：跑之前把一类动作批掉，跑完能对着审计表回看。

为什么不是"撞到 pending 再批"：一次全量跑会依次撞上五六个 L2 模板，每个都
停下来等人点 —— 而人其实早就知道"这个站今天允许我发写请求"。区别只在于：
批的时候看不看得见批的是什么。所以把"批"从「一条已发生的动作」提前成
「一类将要发生的动作」，并且必须先把展开后的清单打印出来（`--dry-run`）。

指纹 = tool|host|param_path|payload_class|level。所以"批一类"绕不开把
这些维度摊开：只写"放行 L2"等于给整个站开写权限，那不是预授权是关闸。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import vhx
from .approvals import LEVEL_ORDER, approval_fingerprint


class GrantError(ValueError):
    pass


@dataclass(frozen=True)
class Spec:
    """一条待批的指纹坐标。`None` 是合法值，意思是"这一维不限定"。"""

    tool: str
    host: str
    param_path: Optional[str]
    payload_class: Optional[str]
    level: str

    @property
    def fp(self) -> str:
        return approval_fingerprint(self.tool, self.host, self.param_path,
                                    self.payload_class, self.level)

    def to_json(self) -> Dict[str, Any]:
        return {"fp": self.fp, "tool": self.tool, "host": self.host,
                "param_path": self.param_path, "payload_class": self.payload_class,
                "level": self.level}


def _template(tid: str) -> Dict[str, Any]:
    for raw in vhx.TEMPLATES:
        if raw["id"] == tid:
            return raw
    raise GrantError("没有这个模板：%s" % tid)


def template_specs(template_ids: Sequence[str], hosts: Sequence[str],
                   level: str = "L2") -> Tuple[List[Spec], List[Dict[str, Any]]]:
    """把模板展开成指纹坐标。

    需要审批但没有 mutator_hints 的模板（CSRF 这种"摘头"而不是"换载荷"的），
    参数路径与载荷类都是 None —— 那一档本来就是"同一请求少一个头"，
    没有额外的维度可限定。
    """
    specs: List[Spec] = []
    skipped: List[Dict[str, Any]] = []
    for tid in template_ids:
        raw = _template(tid)
        if not raw.get("requires_approval"):
            skipped.append({"template_id": tid, "reason": "这个模板不需要审批"})
            continue
        hints = raw.get("mutator_hints") or []
        coords = [(h.get("payload_class"), h.get("param_path")) for h in hints] or [(None, None)]
        for host in hosts:
            for pc, pp in coords:
                spec = Spec("http_probe", host, pp, pc, level)
                if spec not in specs:
                    specs.append(spec)
    return specs, skipped


def expand(ws, template_ids: Sequence[str] = (), hosts: Sequence[str] = (),
           param_path: Optional[str] = None, payload_class: Optional[str] = None,
           level: str = "L2") -> Tuple[List[Spec], List[Dict[str, Any]]]:
    """两种入口：按模板展开，或直接给一条坐标。

    主机默认取 scope.domains —— 那是这次参与约定的那几个域，不是"全网"。
    """
    host_list = [h for h in (hosts or ()) if h] or list(ws.scope.domains)
    if not host_list:
        raise GrantError("scope 里没有域，也没有 --host：不知道要批哪个主机")
    if template_ids:
        if param_path or payload_class:
            raise GrantError("--template 和 --param/--payload 是两条路，选一条")
        return template_specs(template_ids, host_list, level)
    if not (param_path or payload_class):
        raise GrantError("要么给 --template，要么给 --param / --payload 说明要素"
                         "——只写「放行 L2」等于给整个站开写权限")
    return [Spec("http_probe", h, param_path, payload_class, level) for h in host_list], []


def grant(ws, specs: Iterable[Spec], ttl_hours: float = 24.0, by: str = "",
          note: str = "", dry_run: bool = False) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for spec in specs:
        rec = spec.to_json()
        if not dry_run:
            ws.gate.decide(ws.scope.engagement_id, spec.tool, spec.host, spec.param_path,
                           spec.payload_class, spec.level, "approve",
                           decided_by=by or "operator", scope="class",
                           note=note, ttl_hours=ttl_hours)
        rec["ttl_hours"] = ttl_hours
        rows.append(rec)
    return rows


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", ""))
    except ValueError:
        return None


def listing(ws, level: Optional[str] = None) -> List[Dict[str, Any]]:
    now = datetime.utcnow()
    out: List[Dict[str, Any]] = []
    for row in ws.store.list_approvals(ws.scope.engagement_id, level=level):
        exp = _parse(row["expires_at"])
        out.append({
            "fp": row["fp"], "host": row["host"], "param_path": row["param_path"],
            "payload_class": row["payload_class"], "level": row["level"],
            "scope": row["scope"], "decided_by": row["decided_by"],
            "decided_at": row["decided_at"], "expires_at": row["expires_at"],
            "remaining_s": int((exp - now).total_seconds()) if exp else None,
            "note": row["note"],
        })
    return out


def revoke(ws, fp: Optional[str] = None, level: Optional[str] = None) -> int:
    if fp:
        return 1 if ws.store.drop_approval(fp) else 0
    rows = ws.store.list_approvals(ws.scope.engagement_id, level=level)
    return sum(1 for r in rows if ws.store.drop_approval(r["fp"]))


def audit(ws, level: str = "L2", limit: int = 200) -> List[Dict[str, Any]]:
    """看 L2+ 的动作是凭什么放行的。

    这是预授权的另一半：批的时候是"我预计要做"，这里是"实际做了什么"。
    没有这张表，预授权就等于把审批关掉。
    """
    floor = LEVEL_ORDER.get(level, 2)
    out: List[Dict[str, Any]] = []
    for row in ws.store.logs(ws.scope.engagement_id, "ok"):
        lv = row["level"] or "L1"
        if LEVEL_ORDER.get(lv, 9) < floor:
            continue
        detail: Dict[str, Any] = {}
        try:
            detail = json.loads(row["detail_json"] or "{}")
        except ValueError:
            detail = {}
        out.append({
            "ts": row["ts"], "host": row["host"], "url": row["url"], "level": lv,
            "reason": row["reason"] or "", "param_path": detail.get("param_path"),
            "payload_class": detail.get("payload_class"),
            "evidence_id": detail.get("evidence_id"), "status": detail.get("status"),
            "approval_fp": row["approval_fp"],
        })
        if len(out) >= limit:
            break
    return out


def tally(rows: Sequence[Dict[str, Any]]) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for r in rows:
        key = r["reason"] or "(未记录)"
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def _left(seconds: Optional[int]) -> str:
    if seconds is None:
        return "不过期"
    if seconds <= 0:
        return "已过期"
    h, m = seconds // 3600, (seconds % 3600) // 60
    return "%dh%02dm" % (h, m) if h else "%dm" % max(1, m)


def _short(value: Optional[str], width: int = 24) -> str:
    if not value:
        return "-"
    return value if len(value) <= width else value[: width - 1] + "…"


def render_listing(rows: Sequence[Dict[str, Any]]) -> List[str]:
    if not rows:
        return ["还没有预授权：跑 L2 模板时会停在 pending_approval，等一条条批。",
                "想先批再跑：pta grant --root R --template <模板>"]
    head = "%-14s %-16s %-18s %-4s %-8s %s" % ("主机", "参数路径", "载荷", "等级", "剩余", "批给人")
    lines = [head, "-" * len(head)]
    for r in rows:
        lines.append("%-14s %-16s %-18s %-4s %-8s %s" % (
            _short(r["host"], 14), _short(r["param_path"], 16),
            _short(r["payload_class"], 18), r["level"],
            _left(r["remaining_s"]), r["decided_by"] or "-"))
    lines.append("")
    lines.append("共 %d 条；撤销某条：pta revoke --root R --fp <fp>" % len(rows))
    return lines


def render_dry_run(rows: Sequence[Dict[str, Any]],
                   skipped: Sequence[Dict[str, Any]] = ()) -> List[str]:
    lines = ["将批准 %d 条指纹（--dry-run，没有写入）：" % len(rows)]
    for r in rows:
        lines.append("  %s  %-14s %-16s %-18s %s" % (
            r["fp"][:8], r["host"], _short(r["param_path"], 16),
            _short(r["payload_class"], 18), r["level"]))
    for s in skipped:
        lines.append("  跳过 %s：%s" % (s["template_id"], s["reason"]))
    lines.append("确认无误后去掉 --dry-run 再跑一次。有效期 %g 小时。"
                 % (rows[0]["ttl_hours"] if rows else 24))
    return lines


def render_audit(rows: Sequence[Dict[str, Any]]) -> List[str]:
    if not rows:
        return ["还没有 L2+ 的动作记录：跑一次带写/改状态的模板再看。"]
    head = "%-22s %-14s %-16s %-18s %-4s %-16s %s" % (
        "时间(UTC)", "主机", "参数路径", "载荷", "等级", "放行原因", "证据")
    lines = [head, "-" * len(head)]
    for r in rows:
        lines.append("%-22s %-14s %-16s %-18s %-4s %-16s %s" % (
            r["ts"], _short(r["host"], 14), _short(r["param_path"], 16),
            _short(r["payload_class"], 18), r["level"],
            _short(r["reason"], 16), (r["evidence_id"] or "-")[:12]))
    lines.append("")
    lines.append("小计：" + "、".join("%s %d 次" % (k, v) for k, v in tally(rows)))
    return lines
