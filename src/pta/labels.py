# -*- coding: utf-8 -*-
"""人工标注：把「这条判错了」变成能留下来的东西。

为什么需要这一层：判定层再小心，也会有 oracle 被糊过去的时候（相似度骗得过、
502 页长得像、写接口把标记排进队列）。这种事我事后一看就知道，但如果只在我的
脑子里，下一个目标还会踩同一脚。

所以标注要做三件事：

1. **改口径**。`fp` 把 status 改成 refuted，`tp` 改回 confirmed。报告、`pta ls`、
   导出都跟着变——否则我标完了还得自己记着"这条别看"。
2. **留原判**。`confidence` 和 `verdict` 一个字不动，人工结论单独挂在
   `verdict["human_label"]` 里。人和系统的分歧本身是证据：它说明 oracle 在哪一
   类页面上失了准。
3. **留可重放的坐标**。标注时把 target（URL / 方法 / 参数位 / 两个身份）快照
   进 label 表。没有这个，标注就只是"我记得这条是误报"，无法变成回归样本。
"""
from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from .poc import PocError
from .poc import load as load_poc

FP = "fp"
TP = "tp"
_LABELS = (FP, TP)


class LabelError(ValueError):
    pass


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _target_of(ws, finding_row) -> Dict[str, Any]:
    """把这条结论的"打点坐标"还原出来，供以后重放。

    还原不出来不算错——旧库、证据被删、只到 pending 的结论都可能没有完整请求。
    这时给一个空 target，标注照样成立（人知道这是误报就行），只是没法当回归样本。
    """
    target: Dict[str, Any] = {}
    try:
        poc = load_poc(ws, finding_row["id"])
    except (PocError, KeyError):
        return target
    target["url"] = poc.url
    target["method"] = poc.method
    if poc.body:
        try:
            target["body_json"] = json.loads(poc.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            target["body_b64"] = base64.b64encode(poc.body).decode("ascii")

    roles: Dict[str, str] = {}
    try:
        roles = json.loads(finding_row["verdict_json"] or "{}").get("roles") or {}
    except ValueError:
        roles = {}
    for eid, role in roles.items():
        base = str(role).split("+")[0]
        if base not in ("probe", "baseline"):
            continue
        row = ws.store.get_evidence_row(eid)
        if row is None:
            continue
        if base == "probe":
            target.setdefault("identity_probe", row["identity"])
            target.setdefault("param_path", row["param_path"])
            if not target.get("method") and row["method"]:
                target["method"] = row["method"]
        else:
            target.setdefault("identity_baseline", row["identity"])
    return target


def mark(ws, finding_id: Optional[str] = None, last: bool = False, label: str = FP,
         note: str = "", by: str = "", clear: bool = False) -> Dict[str, Any]:
    """给一条结论打标（或撤销标注）。返回可直接打印的摘要。"""
    if label not in _LABELS:
        raise LabelError("标注只有两种：fp（其实是误报）、tp（确实是洞）；收到 %r" % (label,))

    row = None
    if finding_id:
        row = ws.store.get_finding(finding_id)
        if row is None:
            raise LabelError("没有这条结论：%s" % finding_id)
    elif last:
        row = ws.store.latest_finding(ws.scope.engagement_id)
        if row is None:
            raise LabelError("工作区里还没有任何结论：先跑 `pta run`")
    else:
        raise LabelError("要么给 finding_id，要么加 --last")

    verdict = {}
    try:
        verdict = json.loads(row["verdict_json"] or "{}")
    except ValueError:
        verdict = {}
    human = verdict.get("human_label") or {}
    # 恢复时的"原判"必须从标注时存下来的那份取。finding.status 已经被标注改过了，
    # 从它取会得到"refuted"，撤销之后还是 refuted——标注看起来成功了，其实没撤掉。
    original = human.get("original_status") or verdict.get("status") or row["status"]

    if clear:
        verdict.pop("human_label", None)
        ws.store.set_finding_status(row["id"], original, None, verdict)
        return {"ok": True, "finding_id": row["id"], "cleared": True,
                "status": original, "original_status": original}

    target = _target_of(ws, row)
    stamp = _now()
    human = {"label": label, "note": note, "by": by, "at": stamp,
             "original_status": original, "target": target}
    verdict["human_label"] = human
    new_status = "refuted" if label == FP else "confirmed"

    ws.store.put_label({
        "engagement_id": ws.scope.engagement_id,
        "finding_id": row["id"],
        "template_id": row["template_id"],
        "label": label,
        "note": note,
        "by_who": by,
        "target": target,
        "verdict": {"status": original, "confidence": row["confidence"]},
        "created_at": stamp,
    })
    ws.store.set_finding_status(row["id"], new_status, "mark:%s" % label, verdict)

    return {
        "ok": True,
        "finding_id": row["id"],
        "template_id": row["template_id"],
        "label": label,
        "status": new_status,
        "original_status": original,
        "confidence": row["confidence"],
        "note": note,
        "target": target,
        "replayable": bool(target.get("url")),
    }


def listing(ws, label: Optional[str] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in ws.store.labels(ws.scope.engagement_id, label):
        out.append({
            "id": r["id"],
            "finding_id": r["finding_id"],
            "template_id": r["template_id"],
            "label": r["label"],
            "note": r["note"],
            "by": r["by_who"],
            "at": r["created_at"],
        })
    return out


def rate(fp: int, tp: int) -> Optional[float]:
    """误报率只在"人看过"的分母上算。没标过就是 None——不是 0%。
    把没标过的算成 0% 会让人误以为模板很准。"""
    total = (fp or 0) + (tp or 0)
    if total <= 0:
        return None
    return float(fp) / float(total)


def stats(ws) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in ws.store.label_stats(ws.scope.engagement_id):
        fp, tp = int(r["fp"] or 0), int(r["tp"] or 0)
        out.append({
            "template_id": r["template_id"],
            "findings": int(r["findings"] or 0),
            "confirmed": int(r["confirmed"] or 0),
            "hypothesis": int(r["hypothesis"] or 0),
            "refuted": int(r["refuted"] or 0),
            "pending": int(r["pending"] or 0),
            "fp": fp,
            "tp": tp,
            "fp_rate": rate(fp, tp),
        })
    return out
