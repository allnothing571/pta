"""审批门。副作用分级 L0–L3 的唯一执行点。

指纹 = sha256(tool|host|param_path|payload_class|level)[:24]
- scope=once  只对这一条指纹有效，用后即焚
- scope=class 同类动作 24h 内可复用（同 host + 同 param_path + 同 payload_class）
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from .store import Store

LEVEL_ORDER = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}


def approval_fingerprint(tool: str, host: str, param_path: Optional[str],
                         payload_class: Optional[str], level: str) -> str:
    raw = "%s|%s|%s|%s|%s" % (tool, host, param_path or "-", payload_class or "-", level)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def resolve_pending(store: Store, engagement_id: str, fp: str) -> Optional[Dict[str, Any]]:
    """审批上下文：先查 approval 表；没有就从 action_log 的 pending 记录反推。

    probe 触发 pending_approval 时只写 action_log（还没人做决定，approval 表里没有行），
    所以"批一条待审动作"必须能从日志还原出 host/param_path/payload_class/level。
    """
    row = store.get_approval(fp)
    if row is not None:
        return row
    for log in reversed(store.logs(engagement_id, "pending_approval")):
        if log["approval_fp"] != fp:
            continue
        detail = json.loads(log["detail_json"] or "{}")
        return {
            "engagement_id": log["engagement_id"], "tool": log["tool"],
            "host": log["host"], "param_path": detail.get("param_path"),
            "payload_class": detail.get("payload_class"), "level": log["level"] or "L2",
        }
    return None


def _now() -> datetime:
    return datetime.utcnow()


class ApprovalGate:
    def __init__(self, store: Store, level_threshold: str = "L2"):
        self.store = store
        self.level_threshold = level_threshold

    def needs_approval(self, level: str) -> bool:
        return LEVEL_ORDER.get(level, 9) >= LEVEL_ORDER[self.level_threshold]

    def check(self, engagement_id: str, tool: str, host: str, param_path: Optional[str],
              payload_class: Optional[str], level: str) -> Tuple[bool, str, str]:
        """返回 (allowed, fp, reason)。不抛异常，调用方决定记什么日志。"""
        fp = approval_fingerprint(tool, host, param_path, payload_class, level)
        if not self.needs_approval(level):
            return True, fp, "auto:%s" % level
        row = self.store.get_approval(fp)
        if row is None:
            return False, fp, "pending_approval"
        if row["decision"] != "approve":
            return False, fp, "rejected:%s" % (row["note"] or "")
        expires = row["expires_at"]
        if expires and datetime.fromisoformat(expires.replace("Z", "")) < _now():
            return False, fp, "approval_expired"
        return True, fp, "approved:%s" % row["scope"]

    def decide(self, engagement_id: str, tool: str, host: str, param_path: Optional[str],
               payload_class: Optional[str], level: str, decision: str,
               decided_by: str = "operator", scope: str = "once", note: str = "",
               ttl_hours: float = 24.0) -> str:
        assert decision in ("approve", "reject", "modify")
        fp = approval_fingerprint(tool, host, param_path, payload_class, level)
        expires = None
        if scope == "class" and decision == "approve":
            # ttl_hours 默认 24：预授权不该是永久的，过期回到 pending 才是默认安全状态
            expires = (_now() + timedelta(hours=ttl_hours)).isoformat(timespec="seconds") + "Z"
        self.store.put_approval({
            "fp": fp,
            "engagement_id": engagement_id,
            "decision": decision,
            "scope": scope,
            "tool": tool,
            "host": host,
            "param_path": param_path,
            "payload_class": payload_class,
            "level": level,
            "decided_by": decided_by,
            "decided_at": _now().isoformat(timespec="seconds") + "Z",
            "expires_at": expires,
            "note": note,
        })
        return fp

    def consume_once(self, fp: str) -> None:
        """once 审批用后即焚：改成 used，防止越权复用。"""
        row = self.store.get_approval(fp)
        if row is not None and row["scope"] == "once":
            self.store.conn.execute(
                "UPDATE approval SET decision='used' WHERE fp=?", (fp,)
            )
            self.store.conn.commit()
