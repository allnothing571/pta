# -*- coding: utf-8 -*-
"""项目视图：把「这个项目现在到哪一步」从产物里算出来。

三条边界，写在这里免得后来人改坏：

1. **阶段不落库。** `stage` 每次都从 scope.json / vault.json / index.sqlite /
   discover.json 现算。存一份就会和真相分叉，而分叉后的状态比没有状态更坏——
   你会相信它。这也是 `targets.py` 那句「台账只记路径，不复制真相」的延续。
2. **交付状态例外，存台账。** 交付是人的决定，不是工作区的真相：目录被删、
   被重建、被拷走，都不该让「这一轮已经交出去了」消失或复活。它只活在一处。
3. **读不到就说读不到。** 候选数是 `None` 而不是 0——「没跑过 discover」和
   「跑了但一个候选都没有」是两件事，混在一起会让人对着 0 找 bug。
"""
from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from . import targets
from .scope import Scope
from .workspace import Workspace, init_workspace, open_workspace

# (机器 id, 中文标签)。顺序就是「进行中」的推进顺序，列表筛选按这个顺序排。
STAGES: Tuple[Tuple[str, str], ...] = (
    ("missing", "工作区不在了"),
    ("delivered", "已交付"),
    ("no_identity", "待登录态"),
    ("no_recon", "待侦察"),
    ("no_verdict", "待判定"),
    ("review", "待复核"),
    ("no_confirmed", "判完无真结论"),
    ("deliverable", "可交付"),
)

# 界面上的「进行中」= 这五档。审计口径里它们都需要人再动一手。
IN_FLIGHT: Tuple[str, ...] = ("no_identity", "no_recon", "no_verdict", "review", "no_confirmed")

_LABEL = dict(STAGES)
_ORDER = {sid: i for i, (sid, _lbl) in enumerate(STAGES)}


def label_of(stage: str) -> str:
    return _LABEL.get(stage, stage)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class ProjectError(ValueError):
    """带机器可读 code 的错误：api 层照着它选 HTTP 状态码，不再靠字符串猜。"""

    def __init__(self, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra


def _read_json(path: str) -> Optional[Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _ro_conn(db_path: str) -> Optional[sqlite3.Connection]:
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path.replace("\\", "/"), uri=True,
                               timeout=2.0)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error:
        return None


def _identities(vault_path: str) -> List[str]:
    data = _read_json(vault_path) or {}
    if not isinstance(data, dict):
        return []
    out = []
    for ref in data:
        if not isinstance(ref, str) or not ref.startswith("cred/"):
            continue
        parts = ref.split("/")
        if len(parts) >= 3 and parts[1] and parts[1] not in out:
            out.append(parts[1])
    return sorted(out)


def _pending_count(conn: sqlite3.Connection, engagement_id: str) -> int:
    """和 api._pending 同一套口径：有 pending_approval、approval 表里还没决定。"""
    decided = {r[0] for r in conn.execute("SELECT fp FROM approval").fetchall()}
    n = 0
    for row in conn.execute(
            "SELECT approval_fp, detail_json FROM action_log "
            "WHERE engagement_id=? AND decision='pending_approval'",
            (engagement_id,)).fetchall():
        fp = row["approval_fp"]
        if not fp:
            try:
                fp = (json.loads(row["detail_json"] or "{}") or {}).get("fp")
            except (TypeError, ValueError):
                fp = None
        if fp and fp not in decided:
            n += 1
    return n


# ---------------------------------------------------------------- 事实

def facts(root: str, row: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """一个工作区当前的全部可数事实。只读，不会建库、不会改文件。"""
    row = row or {}
    out: Dict[str, Any] = {
        "root": os.path.abspath(root) if root else "",
        "exists": False,
        "error": "",
        "engagement_id": row.get("engagement_id") or "",
        "domains": list(row.get("domains") or ()),
        "allowed_ports": [],
        "allow_private": False,
        "expires_at": None,
        "identities": [],
        "evidence": 0,
        "recon_pages": 0,
        "findings": {"total": 0, "confirmed": 0, "hypothesis": 0, "refuted": 0},
        "pending": 0,
        "candidates": None,
        "harvested": None,
        "graph_edges": None,
        "last_activity": "",
        "delivered_at": row.get("delivered_at"),
        "delivered_by": row.get("delivered_by"),
        "delivered_note": row.get("delivered_note") or "",
        "created_at": row.get("created_at") or "",
        "last_used_at": row.get("last_used_at") or "",
    }
    if not root or not os.path.isdir(root):
        out["error"] = "目录不在了"
        return out

    scope = _read_json(os.path.join(root, "scope.json"))
    if not isinstance(scope, dict):
        out["error"] = "scope.json 读不出来（没 init 过，或者文件坏了）"
        return out

    out["exists"] = True
    out["engagement_id"] = scope.get("engagement_id") or out["engagement_id"]
    out["domains"] = list(scope.get("domains") or out["domains"])
    out["allowed_ports"] = list(scope.get("allowed_ports") or ())
    out["allow_private"] = bool(scope.get("allow_private"))
    out["expires_at"] = scope.get("expires_at")
    out["identities"] = _identities(os.path.join(root, "vault.json"))

    db_path = os.path.join(root, "index.sqlite")
    if os.path.exists(db_path):
        conn = _ro_conn(db_path)
        if conn is None:
            out["error"] = "index.sqlite 打不开"
        else:
            try:
                eng = out["engagement_id"]
                out["evidence"] = int(conn.execute(
                    "SELECT COUNT(*) FROM evidence WHERE engagement_id=?",
                    (eng,)).fetchone()[0] or 0)
                out["recon_pages"] = int(conn.execute(
                    "SELECT COUNT(*) FROM evidence WHERE engagement_id=? AND label='recon'",
                    (eng,)).fetchone()[0] or 0)
                for r in conn.execute(
                        "SELECT status, COUNT(*) AS n FROM finding WHERE engagement_id=? "
                        "GROUP BY status", (eng,)).fetchall():
                    status = r["status"]
                    n = int(r["n"] or 0)
                    if status in ("confirmed", "hypothesis", "refuted"):
                        out["findings"][status] = n
                        out["findings"]["total"] += n
                out["pending"] = _pending_count(conn, eng)
                row_last = conn.execute(
                    "SELECT MAX(ts_last) FROM evidence WHERE engagement_id=?",
                    (eng,)).fetchone()
                out["last_activity"] = (row_last[0] if row_last else "") or ""
            except sqlite3.Error as exc:
                out["error"] = "index.sqlite 读不出来（%s）" % exc
            finally:
                conn.close()
    else:
        # 刚 init、还没跑过。这不是错误，别在界面上标成红的
        out["last_activity"] = ""

    disc = _read_json(os.path.join(root, "discover.json"))
    if isinstance(disc, dict):
        counts = disc.get("counts") or {}
        if isinstance(counts, dict):
            if "suggestions" in counts:
                out["candidates"] = int(counts.get("suggestions") or 0)
            if "harvested" in counts:
                out["harvested"] = int(counts.get("harvested") or 0)
            if "graph_edges" in counts:
                out["graph_edges"] = int(counts.get("graph_edges") or 0)

    if not out["last_activity"]:
        out["last_activity"] = out["last_used_at"] or out["created_at"] or ""
    return out


def stage_of(f: Dict[str, Any]) -> str:
    """纯函数：给一份 facts，说它停在哪一档。顺序就是优先级，别随手调。"""
    if not f.get("exists"):
        return "missing"
    if f.get("delivered_at"):
        return "delivered"
    if not f.get("identities"):
        return "no_identity"
    if not f.get("evidence"):
        return "no_recon"
    findings = f.get("findings") or {}
    if not findings.get("total"):
        return "no_verdict"
    if f.get("pending") or findings.get("hypothesis"):
        return "review"
    if not findings.get("confirmed"):
        return "no_confirmed"
    return "deliverable"


def is_deliverable(f: Dict[str, Any]) -> bool:
    return stage_of(f) == "deliverable"


def why_stopped(f: Dict[str, Any]) -> str:
    """「为什么停在这儿」的一句话。数字都来自 facts，不写形容词。"""
    st = stage_of(f)
    findings = f.get("findings") or {}
    if st == "missing":
        return f.get("error") or "目录不在了"
    if st == "delivered":
        who = f.get("delivered_by") or "operator"
        return "已经交付：%s（%s）" % (f.get("delivered_at") or "", who)
    if st == "no_identity":
        return "工作区里没有任何登录态：先导入一个 cookie / 请求头"
    if st == "no_recon":
        return "还没有任何证据：先侦察一次，或者直接跑一个模板"
    if st == "no_verdict":
        cand = f.get("candidates")
        cand_txt = "还没跑过 discover" if cand is None else "%d 个候选" % cand
        return "%d 条证据、%s，还没跑出结论" % (f.get("evidence") or 0, cand_txt)
    if st == "review":
        bits = []
        if findings.get("hypothesis"):
            bits.append("%d 条 hypothesis 没复核" % findings["hypothesis"])
        if f.get("pending"):
            bits.append("%d 条 L2 动作等人放行" % f["pending"])
        return "有结论但还没定下来：" + "、".join(bits or ["还有未处理的条目"])
    if st == "no_confirmed":
        return "%d 条结论全是否定（refuted）：换候选或换模板再跑一轮" % findings.get("refuted", 0)
    return ("%d 条 confirmed，没有待审批、也没有未复核的 hypothesis"
            % findings.get("confirmed", 0))


def steps_of(f: Dict[str, Any]) -> List[Dict[str, str]]:
    """六步时间线。`current` 只有一个：第一个没做完的。"""
    findings = f.get("findings") or {}
    delivered = bool(f.get("delivered_at"))
    checks: List[Tuple[str, str, str, bool]] = [
        ("workspace", "建工作区",
         ("%s" % f.get("root")) if f.get("exists") else (f.get("error") or "目录不在了"),
         bool(f.get("exists"))),
        ("identity", "有登录态",
         ("%d 个身份：%s" % (len(f.get("identities") or []), ", ".join(f.get("identities") or []))
          if f.get("identities") else "还没有导入身份"),
         bool(f.get("identities"))),
        ("recon", "侦察到资产",
         ("%d 条证据（其中 %d 页侦察）" % (f.get("evidence") or 0, f.get("recon_pages") or 0)
          if f.get("evidence") else "一条证据都没有"),
         bool(f.get("evidence"))),
        ("verdict", "出了结论",
         ("confirmed %d / hypothesis %d / refuted %d"
          % (findings.get("confirmed", 0), findings.get("hypothesis", 0),
             findings.get("refuted", 0))
          if findings.get("total") else "还没跑模板"),
         bool(findings.get("total"))),
        ("review", "复核完",
         ("还有 %d 条 hypothesis、%d 条待审批"
          % (findings.get("hypothesis", 0), f.get("pending") or 0))
         if (findings.get("hypothesis") or f.get("pending")) else "没有悬着的条目",
         bool(findings.get("total")) and not findings.get("hypothesis")
         and not f.get("pending")),
        ("deliver", "交付",
         ("%s（%s）" % (f.get("delivered_at"), f.get("delivered_by") or "operator")
          if delivered else "还没确认交付"),
         delivered),
    ]
    out: List[Dict[str, str]] = []
    current_done = True
    for sid, label, detail, done in checks:
        if not f.get("exists"):
            state = "todo"
        elif done:
            state = "done"
        elif current_done:
            state = "current"
            current_done = False
        else:
            state = "todo"
        out.append({"id": sid, "label": label, "state": state, "detail": detail})
    return out


def next_actions(f: Dict[str, Any]) -> List[Dict[str, str]]:
    """详情页该给哪几个按钮。kind 是前端认识的动作名，不是 URL。"""
    st = stage_of(f)
    if st == "missing":
        return []
    if st == "delivered":
        return [{"kind": "undeliver", "label": "撤回交付"},
                {"kind": "report", "label": "出报告"}]
    if st == "no_identity":
        return [{"kind": "identity", "label": "导入登录态"}]
    if st == "no_recon":
        return [{"kind": "recon", "label": "开始侦察"},
                {"kind": "round", "label": "直接跑一轮"}]
    if st == "no_verdict":
        return [{"kind": "round", "label": "跑一轮"},
                {"kind": "recon", "label": "再侦察一次"}]
    if st == "review":
        return [{"kind": "review", "label": "去复核"},
                {"kind": "round", "label": "跑一轮（继续）"}]
    if st == "no_confirmed":
        return [{"kind": "round", "label": "换候选再跑一轮"},
                {"kind": "recon", "label": "再侦察一次"}]
    return [{"kind": "deliver", "label": "确认已交付"},
            {"kind": "report", "label": "出报告"}]


# ---------------------------------------------------------------- 汇总与筛选

def summarize(row: Dict[str, Any]) -> Dict[str, Any]:
    """台账行 + 现算的事实。列表接口要的扁平结构。"""
    root = row.get("root") or ""
    f = facts(root, row)
    st = stage_of(f)
    findings = f.get("findings") or {}
    parent = os.path.dirname(os.path.abspath(root)) if root else ""
    return {
        "alias": row.get("alias"),
        "name": row.get("name") or row.get("alias"),
        "root": f.get("root") or root,
        "workspace": parent,
        "engagement_id": f.get("engagement_id") or row.get("engagement_id"),
        "domains": list(f.get("domains") or ()),
        "note": row.get("note") or "",
        "stage": st,
        "stage_label": label_of(st),
        "deliverable": st == "deliverable",
        "delivered": bool(f.get("delivered_at")),
        "delivered_at": f.get("delivered_at"),
        "delivered_by": f.get("delivered_by"),
        "identity_count": len(f.get("identities") or []),
        "counts": {
            "evidence": f.get("evidence") or 0,
            "recon_pages": f.get("recon_pages") or 0,
            "confirmed": findings.get("confirmed", 0),
            "hypothesis": findings.get("hypothesis", 0),
            "refuted": findings.get("refuted", 0),
            "pending": f.get("pending") or 0,
            "candidates": f.get("candidates"),
        },
        "last_activity": f.get("last_activity") or "",
        "created_at": row.get("created_at") or "",
        "last_used_at": row.get("last_used_at") or "",
        "exists": bool(f.get("exists")),
        "error": f.get("error") or "",
        "why": why_stopped(f),
    }


def listing(workspace: str = "", stages: Sequence[str] = (), q: str = "",
            rows: Optional[Sequence[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """列表 + 两个 facet。`workspaces` 是工作区目录的父目录——一个项目一个目录，
    真正想按「一批项目在哪」筛的时候，父目录才是那批项目的共同点。

    `rows` 直接给台账行：`pta ui --workspace` 绑死单工作区时，列表页要显示的那一个
    未必在台账里（早期的 `pta init` 不写台账），这时由调用方现造一行传进来。
    """
    if rows is None:
        try:
            rows = targets.entries()
        except targets.LedgerError as exc:
            return {"projects": [], "workspaces": [], "stages": [], "total": 0,
                    "error": str(exc), "ledger": targets.ledger_path()}

    projects = [summarize(r) for r in rows]
    workspaces = sorted({p["workspace"] for p in projects if p["workspace"]})

    needle = (q or "").strip().lower()
    if workspace:
        want = os.path.normcase(os.path.abspath(workspace))
        projects = [p for p in projects
                    if os.path.normcase(p["workspace"]) == want
                    or os.path.normcase(p["root"]).startswith(want + os.sep)]
    if needle:
        def hit(p: Dict[str, Any]) -> bool:
            blob = " ".join([str(p.get("alias") or ""), str(p.get("name") or ""),
                             str(p.get("root") or ""), ",".join(p.get("domains") or [])])
            return needle in blob.lower()
        projects = [p for p in projects if hit(p)]

    counts: Dict[str, int] = {sid: 0 for sid, _lbl in STAGES}
    for p in projects:
        counts[p["stage"]] = counts.get(p["stage"], 0) + 1
    want_stages = {s for s in stages if s}
    if want_stages:
        if "inflight" in want_stages:
            want_stages |= set(IN_FLIGHT)
        projects = [p for p in projects if p["stage"] in want_stages]

    projects.sort(key=lambda p: (p.get("last_activity") or p.get("last_used_at") or "",
                                 p.get("alias") or ""), reverse=True)
    return {
        "projects": projects,
        "workspaces": workspaces,
        "stages": [{"id": sid, "label": lbl, "count": counts.get(sid, 0),
                    "inflight": sid in IN_FLIGHT} for sid, lbl in STAGES],
        "total": len(projects),
        "ledger": targets.ledger_path(),
    }


def detail(alias: str, row: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """一个项目的详情。`row` 给了就不查台账——绑死单工作区时那一行是现造的。"""
    if row is None:
        row = targets.get(alias)
    if row is None:
        raise ProjectError("not_found", "台账里没有 %r" % (alias,))
    project = summarize(row)
    f = facts(row.get("root") or "", row)
    timeline = []
    if row.get("created_at"):
        timeline.append({"ts": row["created_at"], "text": "登记进项目台账"})
    if f.get("last_activity"):
        timeline.append({"ts": f["last_activity"], "text": "最后一次落证据"})
    if f.get("delivered_at"):
        timeline.append({"ts": f["delivered_at"],
                         "text": "交付（%s）" % (f.get("delivered_by") or "operator")})
    return {
        "project": project,
        "stage": project["stage"],
        "stage_label": project["stage_label"],
        "deliverable": project["deliverable"],
        "steps": steps_of(f),
        "facts": f,
        "next": next_actions(f),
        "timeline": timeline,
        "why": why_stopped(f),
    }


# ---------------------------------------------------------------- 新建与交付

_HOST_PRIVATE_SUFFIX = (".localhost", ".local", ".internal", ".test")


def _is_private_host(host: str) -> bool:
    h = (host or "").lower().strip("[]")
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    if h.endswith(_HOST_PRIVATE_SUFFIX):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def slug(name: str) -> str:
    """项目名 -> engagement id。中文保留（它在 JSON 和路径里都没问题），
    空白和斜杠换成 `-`，其余原样。"""
    raw = (name or "").strip()
    out = []
    for ch in raw:
        if ch.isspace() or ch in "\\/:*?\"<>|":
            out.append("-")
        else:
            out.append(ch)
    cleaned = "".join(out).strip("-")
    return cleaned or "project"


def create(name: str, url: str, workspace: str, note: str = "") -> Dict[str, Any]:
    """建目录 + scope + 登记台账。安全边界之外的事（侦察、跑模板）一概不做。"""
    if not (name or "").strip():
        raise ProjectError("bad_name", "项目名不能为空")
    parsed = urlsplit((url or "").strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ProjectError("bad_url", "URL 必须是 http:// 或 https:// 开头，并且带主机名")
    try:
        port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
    except ValueError:
        raise ProjectError("bad_url", "URL 里的端口不是数字")
    if not (workspace or "").strip():
        raise ProjectError("bad_workspace", "工作区目录不能为空")
    if not os.path.isabs(workspace):
        raise ProjectError("bad_workspace", "工作区要给绝对路径（比如 /path/to/ws）")

    root = os.path.abspath(workspace)
    if os.path.exists(os.path.join(root, "scope.json")):
        return _adopt(name.strip(), note or "", root)

    host = parsed.hostname
    ports = {80, 443}
    if port not in (80, 443):
        ports.add(port)
    eng = slug(name)
    scope = Scope(
        engagement_id=eng,
        domains=(host,),
        allow_private=_is_private_host(host),
        rate_per_host=5.0,
        max_requests=9000,
        allowed_ports=tuple(sorted(ports)),
    )
    os.makedirs(root, exist_ok=True)
    scope_path = init_workspace(root, scope)

    row: Optional[Dict[str, Any]] = None
    ledger_error = ""
    try:
        row = targets.register(root, engagement_id=eng, domains=(host,), alias=eng,
                               note=note or "", name=name.strip())
    except targets.LedgerError as exc:
        # 目录和 scope 已经建好了，登记失败不该让整个操作失败（与 pta init 一致）
        ledger_error = str(exc)
    out = {
        "created": {"root": root, "scope": scope_path, "engagement_id": eng},
        "scope": {"domains": [host], "allowed_ports": sorted(ports),
                  "allow_private": _is_private_host(host), "rate_per_host": 5.0,
                  "max_requests": 9000},
    }
    if row is not None:
        out["project"] = summarize(row)
    if ledger_error:
        out["ledger_error"] = ledger_error
    return out


def adopt(root: str, name: str = "", note: str = "") -> Dict[str, Any]:
    """把已有 scope.json 的目录收进台账（`pta ui --workspace` 与新建撞老目录都走这条）。"""
    return _adopt(name, note, root)


def _adopt(name: str, note: str, root: str) -> Dict[str, Any]:
    """目录里已经有 scope.json（pta init 建过、或者从别处搬来的）：收进台账，不重写 scope。

    这里的取舍：别人给的边界（domains / ports / allow_private）我们不改，只把它变成
    台账里的一行；想让 UI 认它，唯一缺的就是这个登记动作。
    """
    existing = targets.get(root)
    if existing is not None:
        raise ProjectError("already_exists", "这个目录已经是一个项目了",
                           alias=existing.get("alias"), root=root)
    f = facts(root)
    if f.get("error"):
        raise ProjectError("bad_workspace",
                           "这个目录里有 scope.json，但读不出来：%s" % f["error"], root=root)
    eng = f.get("engagement_id") or slug(name or os.path.basename(root))
    domains = tuple(f.get("domains") or ())
    try:
        row = targets.register(root, engagement_id=eng, domains=domains, alias=eng,
                               note=note or "", name=name or os.path.basename(root))
    except targets.LedgerError as exc:
        raise ProjectError("ledger_error", str(exc), root=root)
    return {
        "created": {"root": root, "scope": os.path.join(root, "scope.json"),
                    "engagement_id": eng, "imported": True},
        "scope": {"domains": list(domains),
                  "allowed_ports": list(f.get("allowed_ports") or ()),
                  "allow_private": bool(f.get("allow_private")),
                  "rate_per_host": None, "max_requests": None},
        "project": summarize(row),
    }


def deliver(alias: str, delivered: bool = True, note: str = "", by: str = "operator",
            force: bool = False) -> Dict[str, Any]:
    row = targets.get(alias)
    if row is None:
        raise ProjectError("not_found", "台账里没有 %r" % (alias,))
    if delivered:
        f = facts(row.get("root") or "", row)
        st = stage_of(f)
        if st != "deliverable" and not force:
            raise ProjectError("not_deliverable",
                               "现在还不能交付（%s）：%s" % (label_of(st), why_stopped(f)),
                               stage=st, why=why_stopped(f))
        if st != "deliverable":
            note = "强制交付：" + (note or why_stopped(f))
    try:
        row = targets.set_delivery(alias, bool(delivered), by=by, note=note)
    except targets.LedgerError as exc:
        raise ProjectError("ledger_error", str(exc))
    return {"project": summarize(row), "delivered": bool(delivered)}


# ---------------------------------------------------------------- 工作区缓存

def _close_ws(ws: Workspace) -> None:
    try:
        ws.store.close()
    except Exception:                                        # noqa: BLE001 - 淘汰不该抛
        pass


class ProjectBook:
    """alias -> 打开的 Workspace，带 LRU。

    为什么不在启动时全打开：每个工作区都要建 sqlite 连接、读 master key、
    建 CAS 目录。十个项目就是十份句柄，而同一时刻只有一个在前台。
    """

    def __init__(self, cache_size: int = 8, fixed: Optional[Workspace] = None):
        self._cache: "OrderedDict[str, Workspace]" = OrderedDict()
        self._lock = threading.RLock()
        self._cache_size = max(1, int(cache_size))
        self._fixed = fixed

    def fixed_row(self) -> Optional[Dict[str, Any]]:
        """绑死单工作区时，列表/详情用的那一行：台账里有就用台账的（alias 与 `pta ls` 一致），
        没有就现造一行（早期的 `pta init` 不写台账）。"""
        if self._fixed is None:
            return None
        root = os.path.abspath(self._fixed.root)
        try:
            row = targets.get(root)
        except targets.LedgerError:                          # 台账坏了也得能开页面
            row = None
        if row:
            return dict(row)
        base = os.path.basename(root)
        return {"alias": base, "name": base, "root": root}

    @property
    def fixed_alias(self) -> str:
        """绑死单工作区时的项目名；多项目模式返回空串。"""
        row = self.fixed_row()
        return (row or {}).get("alias") or ""

    @property
    def fixed_root(self) -> str:
        return os.path.abspath(self._fixed.root) if self._fixed else ""

    # ---------- 兼容模式 ----------
    @classmethod
    def single(cls, ws: Workspace) -> "ProjectBook":
        """一个 ws 绑死整台服务。demo_ui.py 和 `serve(open_workspace(...))` 走这条，
        行为与多项目改造之前完全一致。"""
        return cls(cache_size=1, fixed=ws)

    def _fixed_alias(self) -> str:
        assert self._fixed is not None
        return os.path.basename(os.path.abspath(self._fixed.root)) or "project"

    # ---------- 解析 ----------
    def aliases(self) -> List[str]:
        if self._fixed is not None:
            return [self._fixed_alias()]
        try:
            return [r.get("alias") for r in targets.entries() if r.get("alias")]
        except targets.LedgerError:
            return []

    def default(self) -> Optional[str]:
        if self._fixed is not None:
            return self._fixed_alias()
        names = self.aliases()
        return names[0] if len(names) == 1 else None

    def resolve(self, alias: Optional[str]) -> str:
        if self._fixed is not None:
            if alias in (None, "", self._fixed_alias()):
                return self._fixed.root
            raise KeyError(alias)
        if not alias:
            alias = self.default()
            if not alias:
                raise KeyError("")
        row = targets.get(alias)
        if row is None or not row.get("root"):
            raise KeyError(alias)
        return row["root"]

    # ---------- 打开 / 淘汰 ----------
    def ws(self, alias: Optional[str] = None) -> Workspace:
        root = self.resolve(alias)
        if self._fixed is not None:
            return self._fixed
        key = os.path.normcase(os.path.realpath(root))
        with self._lock:
            got = self._cache.get(key)
            if got is not None:
                self._cache.move_to_end(key)
                return got
        ws = open_workspace(root)          # 读盘放在锁外：慢 IO 不该堵住别的请求
        with self._lock:
            self._cache[key] = ws
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_size:
                _k, old = self._cache.popitem(last=False)
                _close_ws(old)
        return ws

    def drop(self, alias: str) -> None:
        if self._fixed is not None:
            return
        root = self.resolve(alias)
        key = os.path.normcase(os.path.realpath(root))
        with self._lock:
            old = self._cache.pop(key, None)
        if old is not None:
            _close_ws(old)

    def close_all(self) -> None:
        with self._lock:
            ws_list = list(self._cache.values())
            self._cache.clear()
        for ws in ws_list:
            _close_ws(ws)


# ---------------------------------------------------------------- 后台任务

class JobBusy(RuntimeError):
    def __init__(self, job: "Job"):
        super().__init__("项目 %s 正在跑 %s" % (job.alias, job.kind))
        self.job = job


class Job:
    """一次后台动作（侦察 / 跑一轮 / 出报告）。

    存在的理由：这三件事都会跑几十秒到几分钟。同步等就会把 HTTP 拖死，
    而失败了也只会变成一个没人看的 JSON——和 /api/run 当初的问题一样。
    """

    def __init__(self, alias: str, kind: str, label: str):
        self.run_id = uuid.uuid4().hex[:12]
        self.alias = alias
        self.kind = kind
        self.label = label
        self.state = "queued"          # queued / running / done / failed
        self.started_at = ""
        self.finished_at = ""
        self.result: Dict[str, Any] = {}
        self.error = ""
        self.progress: List[str] = []

    def note(self, text: str) -> None:
        self.progress.append("%s %s" % (_now(), text))
        del self.progress[:-20]        # 只留最近 20 条，进度不是流水账

    def to_json(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id, "alias": self.alias, "kind": self.kind,
            "label": self.label, "state": self.state,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "result": self.result, "error": self.error,
            "progress": list(self.progress),
        }


class JobRegistry:
    """一个项目同时只能有一个任务；全局最多 `limit` 个任务在跑，其余排队。"""

    def __init__(self, bus: Optional[Any] = None, limit: int = 2):
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.RLock()
        self._slots = threading.Semaphore(max(1, int(limit)))
        self._bus = bus

    def get(self, alias: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(alias)

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [j.to_json() for j in self._jobs.values()]

    def start(self, alias: str, kind: str, label: str,
              fn: Callable[[Job], Dict[str, Any]]) -> Job:
        with self._lock:
            cur = self._jobs.get(alias)
            if cur is not None and cur.state in ("queued", "running"):
                raise JobBusy(cur)
            job = Job(alias, kind, label)
            self._jobs[alias] = job
        threading.Thread(target=self._run, args=(job, fn),
                         name="pta-job-%s" % job.run_id, daemon=True).start()
        return job

    def _run(self, job: Job, fn: Callable[[Job], Dict[str, Any]]) -> None:
        self._slots.acquire()
        try:
            job.state = "running"
            job.started_at = _now()
            self._emit("job_started", job)
            out = fn(job)
            job.result = out if isinstance(out, dict) else {"result": out}
            job.state = "done"
        except Exception as exc:                             # noqa: BLE001 - 报给界面
            job.state = "failed"
            job.error = "%s: %s" % (type(exc).__name__, exc)
        finally:
            job.finished_at = _now()
            self._slots.release()
            self._emit("job_finished", job)

    def _emit(self, kind: str, job: Job) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish({"type": kind, "project": job.alias, "job": job.to_json()})
        except Exception:                                    # noqa: BLE001 - 通知失败不影响任务
            pass
