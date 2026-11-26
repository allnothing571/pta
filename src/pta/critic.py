"""Critic：对 confirmed / hypothesis 做独立复核，拥有一票否决。

三条边界：
1. Critic 不发任何请求。它只读证据库（SQLite + CAS）和模板定义。
2. 规则是确定性的，先跑；模型只在规则全过之后可选地做一次二次判断，且只能否决、
   不能提升状态——"confirmed" 的入口永远只有 oracle。
3. 否决是留痕的：finding.status 改成 refuted，overridden_by=critic，critique 写进
   verdict_json，不删记录。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import vhx
from .errors import EvidenceCorrupted, EvidenceNotFound, PtaError, ScopeViolation
from .executor import Finding
from .llm import GuardedModel, ModelUnavailable, build_system
from .workspace import Workspace

# oracle 需要"两条证据配对"才有意义；单条证据判 confirmed 一律否决
PAIRING_ORACLES = frozenset({
    "differential_object_access", "authz_template_diff", "boolean_response_split",
    "timing_distribution_shift", "jwt_acceptance_check", "field_escalation_effect",
    "write_effect_visible",
})

# jwt_acceptance_check 要两条证据，但两条**故意**来自同一身份（合法 token 与伪造 token 都是 A），
# field_escalation_effect 也是同一身份前后两次写入（合法载荷 → 多塞权限字段）；
# timing_distribution_shift 同样只能同身份（基线就是"同一个人不带载荷的同一请求"），
# 越权与否不是它要回答的问题——它回答"是不是注入让它变慢"。
# boolean_response_split 是三次请求同身份（基线 / 1=1 / 1=2），证明的是"参数进了 SQL"，
# 本来就不该有第二个账号参与，拿"同身份"否它等于否掉整类注入。
# 所以它们只参与"证据不足"检查，不参与"同身份"否决——否则结论会被自己误杀。
SAME_IDENTITY_EXEMPT = frozenset({
    "jwt_acceptance_check", "field_escalation_effect", "timing_distribution_shift",
    "boolean_response_split",
})

CRITIQUE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["decision", "reasons"],
    "properties": {
        "decision": {"type": "string", "enum": ["accept", "reject"]},
        "reasons": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": False,
}


@dataclass
class Issue:
    code: str
    detail: str
    severity: str = "block"          # block | warn

    def to_json(self) -> Dict[str, str]:
        return {"code": self.code, "detail": self.detail, "severity": self.severity}


@dataclass
class Critique:
    finding_id: str
    template_id: str
    status: str = "kept"             # kept | vetoed | warned
    blocks: List[Issue] = field(default_factory=list)
    warnings: List[Issue] = field(default_factory=list)
    model_note: str = ""

    def to_json(self) -> Dict[str, Any]:
        return {"finding_id": self.finding_id, "template_id": self.template_id,
                "status": self.status, "model_note": self.model_note,
                "blocks": [i.to_json() for i in self.blocks],
                "warnings": [i.to_json() for i in self.warnings]}


class Critic:
    def __init__(self, ws: Workspace, model=None, on_event=None):
        self.ws = ws
        self.model = model
        self.on_event = on_event
        self._templates = {t["id"]: t for t in vhx.TEMPLATES}

    # ---------- 主入口 ----------
    def review_finding(self, finding: Finding, apply: bool = True) -> Critique:
        crit = self._rules(finding.id, finding.template_id, finding.status,
                           finding.confidence, list(finding.evidence_ids),
                           finding.verdict)
        if not crit.blocks and self.model is not None and finding.status == "confirmed":
            self._model_pass(crit, finding)
        self._settle(crit, apply)
        return crit

    def review_row(self, row, apply: bool = True) -> Critique:
        crit = self._rules(row["id"], row["template_id"], row["status"],
                           float(row["confidence"]),
                           json.loads(row["evidence_ids_json"] or "[]"),
                           json.loads(row["verdict_json"] or "{}"))
        if not crit.blocks and self.model is not None and row["status"] == "confirmed":
            self._model_pass(crit, self._row_view(row))
        self._settle(crit, apply)
        return crit

    def review_all(self, apply: bool = True) -> Dict[str, Any]:
        out: List[Dict[str, Any]] = []
        for row in self.ws.store.list_findings(self.ws.scope.engagement_id):
            if row["status"] not in ("confirmed", "hypothesis"):
                continue
            out.append(self.review_row(row, apply).to_json())
        counts: Dict[str, int] = {}
        for c in out:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        return {"reviewed": len(out), "counts": counts, "critiques": out}

    # ---------- 确定性规则 ----------
    def _rules(self, fid: str, template_id: str, status: str, confidence: float,
               evidence_ids: Sequence[str], verdict: Dict[str, Any]) -> Critique:
        crit = Critique(finding_id=fid, template_id=template_id)
        raw = self._templates.get(template_id)
        if raw is None:
            crit.blocks.append(Issue("template_unknown", "模板 %s 不在加载期数据库" % template_id))
            return crit
        oracle_name = raw["oracle"]["name"]

        if status not in ("confirmed", "hypothesis"):
            return crit
        if not evidence_ids:
            crit.blocks.append(Issue("evidence_empty", "finding 没有任何证据 id"))
            return crit

        rows, missing = self._load_evidence(evidence_ids)
        for ev_id in missing:
            crit.blocks.append(Issue("evidence_missing", "证据 %s 不在库里" % ev_id))
        for code, detail in self._integrity(rows):
            crit.blocks.append(Issue(code, detail))
        for code, detail in self._scope(rows):
            crit.blocks.append(Issue(code, detail))

        if status == "confirmed" and confidence < 0.85:
            crit.blocks.append(Issue(
                "confidence_status_mismatch",
                "状态 confirmed 但 confidence=%.3f < 0.85" % confidence))

        if oracle_name in PAIRING_ORACLES and len(set(evidence_ids)) < 2:
            crit.blocks.append(Issue(
                "counter_evidence_missing",
                "oracle %s 需要至少 2 条配对证据，实际 %d 条" % (oracle_name, len(set(evidence_ids)))))

        identities = {r["identity"] for r in rows if r["method"] != "OOB"}
        if (oracle_name in PAIRING_ORACLES and oracle_name not in SAME_IDENTITY_EXEMPT
                and len(identities) == 1):
            crit.blocks.append(Issue(
                "same_identity",
                "配对证据全部来自同一身份 %s，无法证明越权" % next(iter(identities))))

        for code, detail in self._duplicates(fid, template_id, evidence_ids):
            crit.warnings.append(Issue(code, detail, severity="warn"))
        if verdict.get("skipped"):
            crit.warnings.append(Issue("payload_skipped",
                                       "执行期跳过载荷：%s" % ",".join(verdict["skipped"]),
                                       severity="warn"))
        return crit

    def _load_evidence(self, evidence_ids: Sequence[str]) -> Tuple[List[Any], List[str]]:
        rows, missing = [], []
        for ev_id in evidence_ids:
            row = self.ws.store.get_evidence_row(ev_id)
            if row is None:
                missing.append(ev_id)
            else:
                rows.append(row)
        return rows, missing

    def _integrity(self, rows: Sequence[Any]) -> List[Tuple[str, str]]:
        """只读 CAS 验哈希，不重新发请求（Critic 永不发包）。同一 blob 只报一次。"""
        problems: List[Tuple[str, str]] = []
        seen = set()
        for row in rows:
            sha = row["body_sha256"]
            if sha in seen:
                continue
            seen.add(sha)
            try:
                self.ws.cas.get(row["body_sha256"])
            except EvidenceCorrupted as exc:
                problems.append(("evidence_corrupted", "%s: %s" % (row["evidence_id"], exc)))
            except EvidenceNotFound:
                problems.append(("evidence_blob_missing", "%s: CAS 缺 blob" % row["evidence_id"]))
            except PtaError as exc:
                problems.append(("evidence_unreadable", "%s: %s" % (row["evidence_id"], exc)))
        return problems

    def _scope(self, rows: Sequence[Any]) -> List[Tuple[str, str]]:
        problems: List[Tuple[str, str]] = []
        for row in rows:
            if row["method"] == "OOB":
                continue
            url = "%s://%s:%d%s" % (row["scheme"], row["host"], row["port"], row["raw_path"])
            try:
                self.ws.scope.check_url(url)
            except ScopeViolation as exc:
                problems.append(("evidence_out_of_scope", "%s: %s" % (url, exc)))
            except PtaError:
                pass
        return problems

    def _duplicates(self, fid: str, template_id: str, evidence_ids: Sequence[str]):
        mine = (self.ws.scope.engagement_id, template_id)
        for row in self.ws.store.list_findings(self.ws.scope.engagement_id):
            if row["id"] == fid or row["status"] != "confirmed":
                continue
            if (row["engagement_id"], row["template_id"]) != mine:
                continue
            other = set(json.loads(row["evidence_ids_json"] or "[]"))
            if other and other != set(evidence_ids):
                yield ("duplicate_finding",
                       "同模板已存在另一条 confirmed：%s" % row["id"])

    # ---------- 模型二次判断（只能否决） ----------
    def _model_pass(self, crit: Critique, finding: Any) -> None:
        payload = {
            "template": crit.template_id,
            "status": finding.status,
            "confidence": round(float(finding.confidence), 3),
            "verdict": finding.verdict,
            "evidence": self._evidence_brief(list(finding.evidence_ids)),
        }
        system = build_system(self.ws.scope.engagement_id, self.ws.scope.domains)
        guard = GuardedModel(self.model, on_event=self.on_event)
        try:
            out = guard.ask_json(system, json.dumps(payload, ensure_ascii=False), CRITIQUE_SCHEMA)
        except ModelUnavailable as exc:
            crit.warnings.append(Issue("critic_model_unavailable", str(exc), severity="warn"))
            return
        except PtaError as exc:
            crit.warnings.append(Issue("critic_model_error", str(exc), severity="warn"))
            return
        if out.get("decision") == "reject":
            reasons = out.get("reasons") or ["模型复核否决"]
            crit.blocks.append(Issue("model_veto", "; ".join(str(r) for r in reasons)[:500]))
        crit.model_note = str(out.get("decision", ""))

    def _evidence_brief(self, evidence_ids: Sequence[str]) -> List[Dict[str, Any]]:
        out = []
        for ev_id in evidence_ids:
            row = self.ws.store.get_evidence_row(ev_id)
            if row is None:
                continue
            out.append({"evidence_id": ev_id, "method": row["method"], "host": row["host"],
                        "path": row["raw_path"], "status": row["status"],
                        "identity": row["identity"], "content_type": row["content_type"],
                        "body_len": row["body_len"], "body_sha256": row["body_sha256"][:16]})
        return out

    # ---------- 落库 ----------
    def _settle(self, crit: Critique, apply: bool) -> None:
        if crit.blocks:
            crit.status = "vetoed"
        elif crit.warnings:
            crit.status = "warned"
        else:
            crit.status = "kept"
        if not apply or crit.status == "kept":
            return
        rec = self._find_row(crit.finding_id)
        if rec is None:
            return
        verdict = json.loads(rec["verdict_json"] or "{}")
        verdict["critique"] = crit.to_json()
        status = "refuted" if crit.status == "vetoed" else rec["status"]
        overridden = "critic" if crit.status == "vetoed" else rec["overridden_by"]
        self.ws.store.conn.execute(
            "UPDATE finding SET status=?, verdict_json=?, overridden_by=? WHERE id=?",
            (status, json.dumps(verdict, ensure_ascii=False), overridden, crit.finding_id))
        self.ws.store.conn.commit()
        if self.on_event:
            self.on_event({"type": "critique", "finding_id": crit.finding_id,
                           "status": crit.status, "blocks": [i.code for i in crit.blocks]})

    def _find_row(self, fid: str):
        for row in self.ws.store.list_findings(self.ws.scope.engagement_id):
            if row["id"] == fid:
                return row
        return None

    def _row_view(self, row) -> Finding:
        return Finding(id=row["id"], engagement_id=row["engagement_id"],
                       template_id=row["template_id"], title=row["title"],
                       status=row["status"], confidence=float(row["confidence"]),
                       evidence_ids=json.loads(row["evidence_ids_json"] or "[]"),
                       verdict=json.loads(row["verdict_json"] or "{}"),
                       stop_reason="", requests_used=0)
