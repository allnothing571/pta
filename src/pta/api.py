"""P0 操作台的 HTTP 接口 + 静态页面托管（只用标准库 http.server）。

设计约束：
- 只有一个进程、一个 sqlite 连接，写操作靠 Store 内部的 RLock 串行；
  /api/run 改成后台线程执行，接口立刻返回 202，结果靠 SSE 推。
- 静态资源走白名单，绝不按路径拼文件名（否则就是目录穿越）。
- raw 证据默认不给：要看原字节必须带 confirm=1（P0 规格 /api/evidence/{id}/raw）。
- 多项目：`ProjectBook` 按需打开工作区（LRU），请求用 `X-Pta-Project` 或
  `?project=` 指定项目；一个项目都没有歧义时自动落到唯一那个。`serve(ws)` 仍然
  只服务一个工作区（`ProjectBook.single`），老的调用方一行都不用改。
"""
from __future__ import annotations

import difflib
import io
import json
import mimetypes
import os
import queue
import threading
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from . import projects as proj
from .approvals import resolve_pending
from .events import Bus
from .models import preview_text
from .projects import JobBusy, JobRegistry, ProjectBook, ProjectError
from .workspace import Workspace

UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")

# 文件名 -> content-type。只服务这三个文件，其余一律 404。
STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
}
MAX_PREVIEW = 4000      # 抽屉里展示的正文长度
MAX_RAW = 256 * 1024    # raw 接口单次最多回 256 KiB


# ---------------------------------------------------------------- 辅助函数

def _row_dict(row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def _load_json(text: Optional[str], default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _text_of(cas, sha: str, limit: int = MAX_PREVIEW) -> Tuple[str, bool, bool]:
    """CAS -> (预览文本, 是否截断, 是否二进制)。拿不到内容时抛异常，由调用方处理。"""
    raw = cas.get(sha)
    truncated = len(raw) > limit
    chunk = raw[:limit]
    if b"\x00" in chunk:
        return "", truncated, True
    return preview_text(chunk, limit=limit), truncated, False


def _similarity(a: str, b: str) -> float:
    """按字符序列算相似度。

    早先按"行集合的 Jaccard + 长度比"算，单行 JSON 一旦有一个字段不同
    就直接掉到 0.4 —— 而 operator 看对比页，恰恰是想知道"两个几乎一样
    的 JSON 里哪个字段变了"。difflib 的序列匹配对这类只改一个词的响应
    给出的分值才符合直觉。文本长度在 MAX_PREVIEW 内，成本可以接受。
    """
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return round(float(difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()), 4)


# ---------------------------------------------------------------- 状态快照

def _templates() -> List[Dict[str, Any]]:
    from . import vhx

    out = []
    for raw in vhx.TEMPLATES:
        out.append({
            "id": raw["id"],
            "title": raw.get("title", raw["id"]),
            "category": raw.get("category"),
            "cwe": raw.get("cwe"),
            "side_effect_level": raw.get("side_effect_level"),
            "requires_approval": bool(raw.get("requires_approval")),
            "sequence": (raw.get("probe") or {}).get("sequence")
            or [(raw.get("probe") or {}).get("action")],
        })
    return out


def _findings(ws: Workspace) -> List[Dict[str, Any]]:
    out = []
    for row in ws.store.list_findings(ws.scope.engagement_id):
        verdict = _load_json(row["verdict_json"], {})
        out.append({
            "id": row["id"],
            "template_id": row["template_id"],
            "title": row["title"],
            "status": row["status"],
            "confidence": round(float(row["confidence"] or 0.0), 4),
            "evidence_ids": _load_json(row["evidence_ids_json"], []),
            "rationale": verdict.get("rationale", ""),
            "metrics": verdict.get("metrics", {}),
            "missing_evidence": verdict.get("missing_evidence", []),
            "overridden_by": row["overridden_by"],
            "created_at": row["created_at"],
        })
    return out


def _evidence_brief(row) -> Dict[str, Any]:
    return {
        "evidence_id": row["evidence_id"],
        "label": row["label"],
        "identity": row["identity"],
        "method": row["method"],
        "scheme": row["scheme"],
        "host": row["host"],
        "port": row["port"],
        "raw_path": row["raw_path"],
        "status": row["status"],
        "content_type": row["content_type"],
        "body_len": row["body_len"],
        "samples": row["sample_count"],
        "param_path": row["param_path"],
        "payload_class": row["payload_class"],
        "ts": row["ts_first"],
    }


def _pending(ws: Workspace) -> List[Dict[str, Any]]:
    """pending = action_log 里有 pending_approval、approval 表里还没有决定。"""
    decided = set()
    cur = ws.store.conn.execute("SELECT fp FROM approval")
    for r in cur.fetchall():
        decided.add(r["fp"])
    out = []
    for row in ws.store.logs(ws.scope.engagement_id, "pending_approval"):
        detail = _load_json(row["detail_json"], {})
        fp = row["approval_fp"] or detail.get("fp") or ""
        if not fp or fp in decided:
            continue
        out.append({
            "fp": fp,
            "host": row["host"],
            "url": row["url"] or detail.get("url", ""),
            "level": row["level"],
            "param_path": detail.get("param_path") or row["param_path"],
            "payload_class": detail.get("payload_class") or row["payload_class"],
            "label": detail.get("label", ""),
            "identity": detail.get("identity", ""),
            "ts": row["ts"],
        })
    return out


def state_payload(ws: Workspace, project: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    scope = ws.scope
    evidence = [_evidence_brief(r) for r in ws.store.list_evidence(scope.engagement_id)]
    findings = _findings(ws)
    tally = {"confirmed": 0, "hypothesis": 0, "refuted": 0, "pending_approval": 0}
    for f in findings:
        if f["status"] in tally:
            tally[f["status"]] += 1
    return {
        "engagement": scope.engagement_id,
        "engagement_detail": {
            "id": scope.engagement_id,
            "signed_by": scope.signed_by,
            "expires_at": scope.expires_at,
        },
        "scope": {
            "domains": list(scope.domains),
            "cidrs": list(scope.cidrs),
            "allowed_ports": list(scope.allowed_ports),
            "allow_private": bool(scope.allow_private),
            "egress_proxy": scope.egress_proxy,
            "deny_paths": list(scope.deny_paths),
            "rate_per_host": scope.rate_per_host,
        },
        "budget": ws.budget.snapshot(),
        "breaker": ws.budget.breaker.state if getattr(ws.budget, "breaker", None) else "closed",
        "evidence_count": len(evidence),
        "evidence": evidence[-60:],
        "findings": findings,
        "tally": tally,
        "pending_approvals": _pending(ws),
        "templates": _templates(),
        "oob": {"tokens": len(getattr(ws.probe, "oob_tokens", ()) or ())},
        # 顶部横幅要显示「这个项目叫什么、停在哪一档」，一处算好，前端不再自己推
        "project": project or {},
        "server_time": _now(),
    }


def evidence_detail(ws: Workspace, evidence_id: str) -> Optional[Dict[str, Any]]:
    row = ws.store.get_evidence_row(evidence_id)
    if row is None:
        return None
    detail = _evidence_brief(row)
    detail["headers"] = _load_json(row["headers_json"], [])
    detail["timings"] = [round(x, 3) for x in ws.store.timings(evidence_id)]
    detail["query"] = _load_json(row["query_json"], [])
    detail["asset_node_id"] = row["asset_node_id"]
    request = None
    try:
        blob = ws.cas.get(row["request_blob"])
        request = json.loads(blob.decode("utf-8"))
    except Exception:                                   # noqa: BLE001 - 证据缺失不阻断页面
        request = None
    detail["request"] = request
    try:
        text, truncated, binary = _text_of(ws.cas, row["body_sha256"])
        detail["body_preview"] = text
        detail["body_truncated"] = truncated
        detail["body_binary"] = binary
    except Exception:                                   # noqa: BLE001
        detail["body_preview"] = ""
        detail["body_truncated"] = False
        detail["body_binary"] = True
    return detail


def evidence_raw(ws: Workspace, evidence_id: str) -> Optional[Dict[str, Any]]:
    row = ws.store.get_evidence_row(evidence_id)
    if row is None:
        return None
    raw = ws.cas.get(row["body_sha256"])
    truncated = len(raw) > MAX_RAW
    chunk = raw[:MAX_RAW]
    binary = b"\x00" in chunk
    return {
        "evidence_id": evidence_id,
        "body_sha256": row["body_sha256"],
        "body_len": len(raw),
        "truncated": truncated,
        "binary": binary,
        "text": "" if binary else preview_text(chunk, limit=MAX_RAW),
    }


def evidence_diff(ws: Workspace, a_id: str, b_id: str) -> Optional[Dict[str, Any]]:
    ra = ws.store.get_evidence_row(a_id)
    rb = ws.store.get_evidence_row(b_id)
    if ra is None or rb is None:
        return None
    ta, _, _ = _text_of(ws.cas, ra["body_sha256"])
    tb, _, _ = _text_of(ws.cas, rb["body_sha256"])
    ha = {str(k).lower(): str(v) for k, v in _load_json(ra["headers_json"], [])}
    hb = {str(k).lower(): str(v) for k, v in _load_json(rb["headers_json"], [])}
    changes = []
    for key in sorted(set(ha) | set(hb)):
        va, vb = ha.get(key), hb.get(key)
        if va != vb:
            changes.append({"name": key, "a": va, "b": vb})
    return {
        "a": {
            "evidence_id": a_id, "method": ra["method"], "host": ra["host"],
            "raw_path": ra["raw_path"], "status": ra["status"], "identity": ra["identity"],
            "body_len": ra["body_len"], "body_preview": ta,
        },
        "b": {
            "evidence_id": b_id, "method": rb["method"], "host": rb["host"],
            "raw_path": rb["raw_path"], "status": rb["status"], "identity": rb["identity"],
            "body_len": rb["body_len"], "body_preview": tb,
        },
        "same_url": (ra["scheme"], ra["host"], ra["port"], ra["raw_path"])
        == (rb["scheme"], rb["host"], rb["port"], rb["raw_path"]),
        "body_same": ra["body_sha256"] == rb["body_sha256"],
        "status_same": ra["status"] == rb["status"],
        "identity_same": ra["identity"] == rb["identity"],
        "similarity": _similarity(ta, tb),
        "header_changes": changes,
    }


# ---------------------------------------------------------------- HTTP 层

def _make_handler(book: ProjectBook, bus: Bus, jobs: JobRegistry):
    class Handler(BaseHTTPRequestHandler):
        server_version = "pta-p0/0.1"
        protocol_version = "HTTP/1.1"

        # ---------- 输出 ----------
        def _send(self, code: int, body: bytes, ctype: str,
                  extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, val in (extra or {}).items():
                self.send_header(key, val)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            self._send(code, body, "application/json; charset=utf-8")

        def _static(self, name: str) -> None:
            ctype = STATIC_FILES.get(name)
            if ctype is None:
                return self._json(404, {"error": "not_found"})
            path = os.path.join(UI_DIR, name)
            if not os.path.exists(path):
                return self._json(404, {"error": "ui_not_built", "missing": name})
            with open(path, "rb") as fh:
                data = fh.read()
            self._send(200, data, ctype)

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return {}

        def log_message(self, fmt: str, *args) -> None:      # 静音：CLI 里不刷访问日志
            pass

        # ---------- 项目解析 ----------
        def _alias(self, query: Dict[str, List[str]]) -> str:
            """请求属于哪个项目：头优先，其次 query，最后"只有一个就它"。"""
            # HTTP 头只能是 ISO-8859-1，别名里带中文时客户端会先 percent-encode 再放进来。
            alias = unquote((self.headers.get("X-Pta-Project") or "").strip())
            if not alias:
                alias = (query.get("project") or [""])[0].strip()
            return alias

        def _project(self, query: Dict[str, List[str]]) -> Tuple[Optional[Workspace], str]:
            """解析出 (ws, alias)。解析不出来时已经回过响应，返回 (None, "")。"""
            alias = self._alias(query)
            try:
                ws = book.ws(alias or None)
            except KeyError:
                if not alias:
                    self._json(400, {"error": "project_required",
                                     "projects": book.aliases()})
                else:
                    self._json(404, {"error": "unknown_project", "alias": alias,
                                     "projects": book.aliases()})
                return None, ""
            except (FileNotFoundError, OSError) as exc:
                self._json(409, {"error": "workspace_unavailable", "message": str(exc)})
                return None, ""
            return ws, (alias or book.default() or "")

        def _project_head(self, ws: Workspace, alias: str) -> Dict[str, Any]:
            from . import targets

            try:
                row = targets.get(alias) if alias else targets.get(ws.root)
            except Exception:                                # noqa: BLE001 - 台账坏了不该拖垮页面
                row = None
            if row is None:
                row = {"alias": alias, "root": ws.root}
            try:
                return proj.summarize(row)
            except Exception:                                # noqa: BLE001
                return {"alias": alias, "root": ws.root, "stage": "missing",
                        "stage_label": proj.label_of("missing")}

        # ---------- GET ----------
        def do_HEAD(self) -> None:
            self.do_GET()

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path in ("/app.js", "/style.css"):
                return self._static(path.lstrip("/"))
            if path.startswith("/ui/"):
                # 只按白名单取文件名，绝不拼路径：/ui/../api.py 会落到 404
                return self._static(unquote(path[len("/ui/"):]))

            if path == "/api/projects":
                return self._projects_list(query)

            if path == "/api/jobs":
                want = (query.get("project") or [""])[0].strip()
                rows = jobs.snapshot()
                if want:
                    rows = [r for r in rows if r.get("alias") == want]
                return self._json(200, {"jobs": rows})

            if path.startswith("/api/projects/"):
                rest = path[len("/api/projects/"):].strip("/")
                if not rest or "/" in rest:
                    return self._json(404, {"error": "not_found"})
                try:
                    want = unquote(rest)
                    row = None
                    if book.fixed_alias and want == book.fixed_alias:
                        row = book.fixed_row()
                    return self._json(200, proj.detail(want, row=row))
                except ProjectError as exc:
                    return self._json(404, {"error": exc.code, "message": exc.message})

            if path == "/api/state":
                ws, alias = self._project(query)
                if ws is None:
                    return
                return self._json(200, state_payload(ws, self._project_head(ws, alias)))

            if path == "/api/stream":
                return self._stream(query)

            ws, _alias = self._project(query)
            if ws is None:
                return

            if path.startswith("/api/evidence/"):
                rest = path[len("/api/evidence/"):]
                if "/raw" in rest:
                    eid = unquote(rest.split("/raw")[0])
                    if (query.get("confirm") or ["0"])[0] not in ("1", "true", "yes"):
                        return self._json(403, {"error": "confirm_required",
                                                "hint": "原始字节需要 confirm=1"})
                    payload = evidence_raw(ws, eid)
                    if payload is None:
                        return self._json(404, {"error": "not_found"})
                    return self._json(200, payload)
                if "/diff/" in rest:
                    a_id, b_id = rest.split("/diff/", 1)
                    payload = evidence_diff(ws, unquote(a_id), unquote(b_id))
                    if payload is None:
                        return self._json(404, {"error": "not_found"})
                    return self._json(200, payload)
                payload = evidence_detail(ws, unquote(rest))
                if payload is None:
                    return self._json(404, {"error": "not_found"})
                return self._json(200, payload)

            if path == "/api/logs":
                limit = int((query.get("limit") or ["200"])[0])
                rows = ws.store.logs(ws.scope.engagement_id)[-limit:]
                return self._json(200, [{
                    "id": r["id"], "tool": r["tool"], "host": r["host"],
                    "decision": r["decision"], "reason": r["reason"],
                    "level": r["level"], "approval_fp": r["approval_fp"],
                    "ts": r["ts"],
                } for r in rows])

            return self._json(404, {"error": "not_found"})

        def _projects_list(self, query: Dict[str, List[str]]) -> None:
            # 绑死单工作区时列表里就那一个：台账里有它就用那一行，没有就现造一行，
            # 而不是让页面看着像空的。
            rows = [book.fixed_row()] if book.fixed_alias else None
            try:
                payload = proj.listing(
                    workspace=(query.get("workspace") or [""])[0],
                    stages=tuple(query.get("stage") or ()),
                    q=(query.get("q") or [""])[0],
                    rows=rows,
                )
            except Exception as exc:                         # noqa: BLE001 - 坏台账报给界面
                return self._json(500, {"error": "listing_failed",
                                        "message": "%s: %s" % (type(exc).__name__, exc)})
            return self._json(200, payload)

        def _stream(self, query: Optional[Dict[str, List[str]]] = None) -> None:
            want = ((query or {}).get("project") or [""])[0].strip() \
                or (self.headers.get("X-Pta-Project") or "").strip()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = bus.subscribe()
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while True:
                    try:
                        ev = q.get(timeout=15.0)
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        continue
                    # 按项目过滤在服务端做：一个界面只关心自己那个项目的事件，
                    # 但全局统计（job 完成）也值得看，所以没带 project 时全推。
                    if want and ev.get("project") not in (None, "", want):
                        continue
                    data = json.dumps(ev, ensure_ascii=False, default=str)
                    self.wfile.write(("event: %s\ndata: %s\n\n"
                                      % (ev.get("type", "message"), data)).encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                bus.unsubscribe(q)

        # ---------- POST ----------
        def do_POST(self) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            body = self._body()

            if path == "/api/projects":
                return self._create_project(body)

            if path.startswith("/api/projects/"):
                rest = path[len("/api/projects/"):].strip("/")
                bits = rest.split("/")
                if len(bits) == 2 and bits[1] in ("deliver", "identity", "recon",
                                                  "round", "report"):
                    return self._project_action(unquote(bits[0]), bits[1], body)
                return self._json(404, {"error": "not_found"})

            ws, alias = self._project(query)
            if ws is None:
                return

            if path.startswith("/api/approvals/") and path.endswith("/decide"):
                fp = unquote(path[len("/api/approvals/"):-len("/decide")])
                row = resolve_pending(ws.store, ws.scope.engagement_id, fp)
                if row is None:
                    return self._json(404, {"error": "unknown_fp"})
                decision = body.get("decision", "approve")
                if decision not in ("approve", "reject", "modify"):
                    return self._json(400, {"error": "bad_decision"})
                scope = body.get("scope", "once")
                if scope not in ("once", "class"):
                    return self._json(400, {"error": "bad_scope"})
                ws.gate.decide(
                    engagement_id=row["engagement_id"], tool=row["tool"], host=row["host"] or "",
                    param_path=row["param_path"] or None,
                    payload_class=row["payload_class"] or None, level=row["level"] or "L2",
                    decision=decision, scope=scope, note=body.get("note", ""),
                )
                bus.publish({"type": "approval_decided", "fp": fp, "decision": decision,
                             "scope": scope})
                return self._json(200, {"ok": True, "fp": fp, "decision": decision})

            if path == "/api/run":
                return self._start_run(body, ws, alias)

            if path == "/api/plan":
                from .planner import Planner

                model = _model_from(body.get("model"))
                plan = Planner(ws, model=model,
                               max_candidates=int(body.get("max_candidates", 5)),
                               on_event=bus.publish).plan()
                return self._json(200, plan.to_json())

            if path == "/api/critic":
                from .critic import Critic

                model = _model_from(body.get("model"))
                out = Critic(ws, model=model, on_event=bus.publish).review_all(
                    apply=bool(body.get("apply", True)))
                return self._json(200, out)

            if path.startswith("/api/findings/") and path.endswith("/override"):
                fid = unquote(path[len("/api/findings/"):-len("/override")])
                status = body.get("status", "refuted")
                if status not in ("confirmed", "hypothesis", "refuted"):
                    return self._json(400, {"error": "bad_status"})
                cur = ws.store.conn.execute("SELECT id FROM finding WHERE id=?", (fid,))
                if cur.fetchone() is None:
                    return self._json(404, {"error": "unknown_finding"})
                with ws.store._lock:
                    ws.store.conn.execute(
                        "UPDATE finding SET status=?, overridden_by=? WHERE id=?",
                        (status, body.get("by", "operator"), fid),
                    )
                    ws.store.conn.commit()
                bus.publish({"type": "finding_overridden", "id": fid, "status": status})
                return self._json(200, {"ok": True, "id": fid, "status": status})

            return self._json(404, {"error": "not_found"})

        # ---------- 项目：新建 / 动作 ----------
        def _create_project(self, body: Dict[str, Any]) -> None:
            try:
                out = proj.create(
                    name=str(body.get("name") or ""),
                    url=str(body.get("url") or ""),
                    workspace=str(body.get("workspace") or ""),
                    note=str(body.get("note") or ""),
                )
            except ProjectError as exc:
                status = {"already_exists": 409, "bad_url": 400, "bad_workspace": 400,
                          "bad_name": 400, "ledger_error": 500}.get(exc.code, 400)
                payload = {"error": exc.code, "message": exc.message}
                payload.update(exc.extra)
                return self._json(status, payload)
            bus.publish({"type": "project_created",
                         "project": (out.get("project") or {}).get("alias")})
            return self._json(201, out)

        def _project_action(self, alias: str, action: str, body: Dict[str, Any]) -> None:
            if action == "deliver":
                try:
                    out = proj.deliver(
                        alias,
                        delivered=bool(body.get("delivered", True)),
                        note=str(body.get("note") or ""),
                        by=str(body.get("by") or "operator"),
                        force=bool(body.get("force")),
                    )
                except ProjectError as exc:
                    status = {"not_found": 404, "not_deliverable": 409,
                              "ledger_error": 500}.get(exc.code, 400)
                    payload = {"error": exc.code, "message": exc.message}
                    payload.update(exc.extra)
                    return self._json(status, payload)
                bus.publish({"type": "project_delivered", "project": alias,
                             "delivered": out["delivered"]})
                return self._json(200, out)

            if action == "identity":
                return self._import_identity(alias, body)

            return self._start_job(alias, action, body)

        def _import_identity(self, alias: str, body: Dict[str, Any]) -> None:
            from . import credentials

            try:
                ident = credentials.check_identity(str(body.get("identity") or ""))
                ws = book.ws(alias)
            except credentials.CredentialError as exc:
                return self._json(400, {"error": "bad_identity", "message": str(exc)})
            except KeyError:
                return self._json(404, {"error": "unknown_project", "alias": alias})

            heads: Dict[str, str] = {}
            cookie = str(body.get("cookie") or "").strip()
            if cookie:
                try:
                    heads["cookie"] = credentials.parse_cookie_file(cookie)
                except Exception as exc:                     # noqa: BLE001
                    return self._json(400, {"error": "bad_cookie", "message": str(exc)})
            for name, value in (body.get("headers") or {}).items():
                if str(name).strip() and str(value).strip():
                    heads[str(name).strip().lower()] = str(value).strip()
            if not heads:
                return self._json(400, {"error": "no_headers",
                                        "message": "给 cookie 或者至少一个请求头"})
            for name, value in heads.items():
                ws.vault.put("cred/%s/%s" % (ident, name), value)
            bus.publish({"type": "identity_imported", "project": alias, "identity": ident})
            return self._json(200, {
                "ok": True, "identity": ident,
                "saved": [{"name": n, "value": credentials.mask(v)} for n, v in heads.items()],
                "project": self._project_head(ws, alias),
            })

        def _start_job(self, alias: str, action: str, body: Dict[str, Any]) -> None:
            try:
                ws = book.ws(alias)
            except KeyError:
                return self._json(404, {"error": "unknown_project", "alias": alias})
            except (FileNotFoundError, OSError) as exc:
                return self._json(409, {"error": "workspace_unavailable",
                                        "message": str(exc)})

            labels = {"recon": "侦察", "round": "跑一轮", "report": "出报告"}
            runners = {"recon": _job_recon, "round": _job_round, "report": _job_report}
            fn = runners[action]
            job_fn = lambda job: fn(ws, job, body)          # noqa: E731 - 一行闭包更清楚
            try:
                job = jobs.start(alias, action, labels[action], job_fn)
            except JobBusy as exc:
                return self._json(409, {"error": "job_running", "job": exc.job.to_json()})
            return self._json(202, {"ok": True, "job": job.to_json()})


        def _start_run(self, body: Dict[str, Any], ws: Workspace, alias: str) -> None:
            from . import vhx
            from .executor import Executor, Target

            tid = body.get("template_id") or body.get("template")
            by_id = {t["id"]: t for t in vhx.TEMPLATES}
            if tid not in by_id:
                return self._json(400, {"error": "unknown_template",
                                        "available": sorted(by_id)})
            url = (body.get("url") or "").strip()
            # 没有 scheme 的 URL 会被 scope 判成「只允许 http/https」，然后落一条
            # refuted 结论——一次请求没发出去却污染了账本。这里直接挡掉。
            if not (url.startswith("http://") or url.startswith("https://")):
                return self._json(400, {"error": "bad_url",
                                        "message": "URL 要以 http:// 或 https:// 开头（例：" \
                                                   "https://host/path?id=1）",
                                        "url": url})
            target = Target(
                url=url,
                param_path=body.get("param_path"),
                identity_baseline=body.get("identity_baseline", "none"),
                identity_probe=body.get("identity_probe", "none"),
                control_url=body.get("control_url"),
                method=(body.get("method") or "GET").upper(),
                body_json=body.get("body_json"),
                sample=int(body.get("sample") or 1),
            )
            raw = by_id[tid]
            run_id = uuid.uuid4().hex[:12]
            bus.publish({"type": "run_started", "run_id": run_id, "template_id": tid,
                         "project": alias, "url": target.url,
                         "level": raw.get("side_effect_level")})

            def work() -> None:
                try:
                    from . import overrides as _ov
                    try:
                        tpl = _ov.load_template(ws, tid)[0]
                    except KeyError:
                        tpl = vhx.load(raw)
                    finding = Executor(ws.probe, ws.store, ws.scope.engagement_id,
                                       browser=getattr(ws, "browser", None)).run(
                        tpl, target, run_id=run_id)
                    bus.publish({"type": "run_finished", "run_id": run_id,
                                 "project": alias,
                                 "template_id": tid, "finding_id": finding.id,
                                 "status": finding.status,
                                 "confidence": round(finding.confidence, 4),
                                 "stop_reason": finding.stop_reason})
                except Exception as exc:                     # noqa: BLE001 - 报给界面
                    bus.publish({"type": "run_failed", "run_id": run_id,
                                 "project": alias, "template_id": tid,
                                 "reason": "%s: %s" % (type(exc).__name__, exc)})

            threading.Thread(target=work, name="pta-run-%s" % run_id, daemon=True).start()
            return self._json(202, {"ok": True, "run_id": run_id, "state": "running",
                                    "template_id": tid})

    return Handler


def _model_from(cfg: Optional[Dict[str, Any]]):
    if not cfg:
        return None
    from .llm import OpenAICompatibleClient

    return OpenAICompatibleClient(
        base_url=cfg.get("base_url", ""),
        api_key=cfg.get("api_key", ""),
        model=cfg.get("name", ""),
    )


def _job_recon(ws: Workspace, job: Any, body: Dict[str, Any]) -> Dict[str, Any]:
    from .recon import Recon, write_report

    seeds = body.get("seed") or body.get("seeds") or []
    if isinstance(seeds, str):
        seeds = [seeds]
    seeds = [str(s) for s in seeds if str(s).strip()]
    if not seeds:
        raise ValueError("侦察需要 seed（例如 http://host/）")
    identity = str(body.get("identity") or "").strip()
    if not identity:
        refs = ws.vault.items("cred/")
        identity = next(iter(sorted({r.split("/")[1] for r in refs if r.count("/") >= 2})),
                        "none")
    job.note("侦察 %d 个种子，身份 %s" % (len(seeds), identity))
    rep = Recon(ws,
                max_pages=int(body.get("max_pages") or 25),
                max_depth=int(body.get("max_depth") or 2),
                identity=identity).run(seeds)
    path = write_report(ws, rep)
    job.note("抓了 %d 页、发了 %d 个请求，明细写进 %s" % (len(rep.pages), rep.requests, path))
    return {"pages": len(rep.pages), "requests": rep.requests,
            "skipped": len(rep.skipped), "report": path,
            "seeds": list(rep.seeds)}


def _job_round(ws: Workspace, job: Any, body: Dict[str, Any]) -> Dict[str, Any]:
    from .critic import Critic
    from .planner import EngagementRunner, Planner

    rounds = int(body.get("max_rounds") or 1)
    max_cand = int(body.get("max_candidates") or 5)
    job.note("规划候选（一轮最多 %d 个），跑 %d 轮" % (max_cand, rounds))
    planner = Planner(ws, model=None, max_candidates=max_cand)
    runner = EngagementRunner(
        ws, planner,
        max_rounds=rounds,
        max_candidates=max_cand,
        critic=Critic(ws),
        workers=int(body.get("workers") or 3),
        resume=bool(body.get("resume", True)),
    )
    out = runner.run()
    job.note("跑完：%s" % json.dumps(_slim(out), ensure_ascii=False))
    return _slim(out)


def _job_report(ws: Workspace, job: Any, body: Dict[str, Any]) -> Dict[str, Any]:
    from .report import ReportOptions, export_report

    out_dir = str(body.get("out") or os.path.join(ws.root, "report"))
    job.note("导出到 %s" % out_dir)
    opts = ReportOptions(
        include_bodies=not bool(body.get("no_bodies")),
        redact=not bool(body.get("no_redact")),
        html=bool(body.get("html", True)),
        include_all_evidence=bool(body.get("all_evidence")),
    )
    m = export_report(ws, out_dir, opts)
    job.note("报告里 %s 条结论" % json.dumps(m.get("counts") or {}, ensure_ascii=False))
    return {"out_dir": m["out_dir"], "root_sha256": m["root_sha256"],
            "counts": m["counts"], "verify": m["verify"]}


def _slim(value: Any, depth: int = 0) -> Any:
    """Runner 的 summary 里可能有不可 JSON 化的东西。只留能进 JSON 的那部分。"""
    if depth > 4:
        return str(value)
    if isinstance(value, dict):
        return {str(k): _slim(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_slim(v, depth + 1) for v in value[:200]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def make_server(target: Any, bus: Optional[Bus] = None, host: str = "127.0.0.1",
                port: int = 0, jobs: Optional[JobRegistry] = None,
                cache_size: int = 8) -> Tuple[ThreadingHTTPServer, Bus]:
    """`target` 可以是一个 Workspace（老用法，等价于单项目），也可以是一个 ProjectBook。"""
    bus = bus or Bus()
    if isinstance(target, ProjectBook):
        book = target
    else:
        book = ProjectBook.single(target)
    registry = jobs or JobRegistry(bus=bus)
    httpd = ThreadingHTTPServer((host, port), _make_handler(book, bus, registry))
    httpd.daemon_threads = True
    httpd.book = book                                          # 供调用方关连接
    httpd.jobs = registry
    return httpd, bus


def serve(target: Any, bus: Optional[Bus] = None, host: str = "127.0.0.1",
          port: int = 8080) -> None:
    httpd, _ = make_server(target, bus=bus, host=host, port=port)
    print("操作台: http://%s:%d/" % (host, httpd.server_address[1]))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        try:
            httpd.book.close_all()
        except Exception:                                    # noqa: BLE001
            pass
