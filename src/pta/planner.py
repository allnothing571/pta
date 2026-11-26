"""Planner：看两张图（资产 + 已确认/待验证假设），产出候选动作。

铁律：
1. Planner 不发请求。它只产出 Candidate，真正发送由 Executor 走 http_probe。
2. 模型输出必须过 schema + 业务校验（模板存在、URL 在 scope、去重），否则丢弃。
3. 模型不可用/拒答时显式降级到本地规则，并在 Plan.notes 里写明原因——不静默。
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from . import vhx
from . import graph as glob
from .errors import PtaError, ScopeViolation
from .executor import Executor, Finding, Target
from .llm import (GuardedModel, ModelClient, ModelUnavailable, PlannerBlocked,
                  build_system)
from .workspace import Workspace

MAX_CANDIDATES = 5
MAX_PROMPT_CHARS = 8000

CANDIDATE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["candidates"],
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["template_id", "url"],
                "properties": {
                    "template_id": {"type": "string"},
                    "url": {"type": "string"},
                    "param_path": {"type": ["string", "null"]},
                    "identity_baseline": {"type": "string"},
                    "identity_probe": {"type": "string"},
                    "method": {"type": "string"},
                    "priority": {"type": "number"},
                    "rationale": {"type": "string"},
                    "control_url": {"type": ["string", "null"]},
                },
                "additionalProperties": False,
            },
        },
        "notes": {"type": "string"},
    },
    "additionalProperties": False,
}


@dataclass
class Candidate:
    template_id: str
    url: str
    param_path: Optional[str] = None
    identity_baseline: str = "none"
    identity_probe: str = "none"
    method: str = "GET"
    priority: float = 0.5
    rationale: str = ""
    control_url: Optional[str] = None
    source: str = "rule"              # rule | model

    def key(self) -> Tuple[str, str, str]:
        base = self.url.split("?", 1)[0].rstrip("/")
        return (self.template_id, base.lower(), self.param_path or "-")

    def to_json(self) -> Dict[str, Any]:
        return {"template_id": self.template_id, "url": self.url,
                "param_path": self.param_path, "identity_baseline": self.identity_baseline,
                "identity_probe": self.identity_probe, "method": self.method,
                "priority": round(self.priority, 3), "rationale": self.rationale,
                "control_url": self.control_url, "source": self.source}

    def to_target(self) -> Target:
        return Target(url=self.url, param_path=self.param_path,
                      identity_baseline=self.identity_baseline,
                      identity_probe=self.identity_probe, method=self.method,
                      control_url=self.control_url)


@dataclass
class Plan:
    candidates: List[Candidate] = field(default_factory=list)
    notes: str = ""
    source: str = "heuristic"          # model | heuristic
    degraded: bool = False
    rejected: List[Dict[str, str]] = field(default_factory=list)
    blocked_reason: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return {"candidates": [c.to_json() for c in self.candidates], "notes": self.notes,
                "source": self.source, "degraded": self.degraded,
                "rejected": self.rejected, "blocked_reason": self.blocked_reason}


@dataclass
class Asset:
    url: str
    method: str = "GET"
    params: Tuple[str, ...] = ()
    status: int = 0
    content_type: Optional[str] = None
    hits: int = 1
    identity: str = "none"        # 最后一次见到它时用的是谁的身份（能读到就说明这个身份有权限）
    # 请求体里的字段名。只可能来自 harvest（页面自己发的接口调用），
    # 我们主动构造的请求里 body 是我们自己写的，没有"发现"的意义。
    body_params: Tuple[str, ...] = ()
    # 响应体原文（只在 JSON 且不太大时保留）。graph 靠它抽"这个对象引用了谁"。
    # 刻意不进 to_json：它是给图用的输入，不是给模型看的上下文。
    body: bytes = b""

    def to_json(self) -> Dict[str, Any]:
        return {"url": self.url, "method": self.method, "params": list(self.params),
                "status": self.status, "content_type": self.content_type,
                "hits": self.hits, "identity": self.identity,
                "body_params": list(self.body_params)}


class PlannerState:
    """Planner 能看到的一切。没有原始响应体，只有结构化事实。"""

    def __init__(self, engagement_id: str, domains: Sequence[str], assets: Sequence[Asset],
                 findings: Sequence[Dict[str, Any]], budget: Dict[str, Any],
                 templates: Sequence[Dict[str, Any]],
                 denials: Sequence[Tuple[str, str]] = (),
                 graph: Optional["graph.Graph"] = None):
        self.engagement_id = engagement_id
        self.domains = tuple(domains)
        self.assets = list(assets)
        self.findings = list(findings)
        self.budget = dict(budget)
        self.templates = list(templates)
        # (netloc, url)：本次任务里真实出现过的 401/403 响应，可直接充当拒绝模板
        self.denials = list(denials)
        # 资产之间的邻接关系。没有它 Planner 只能"一个 URL 一个 URL 地看"，
        # 看不见"同一资源换方法""同模板换对象"这类推论。
        self.graph = graph if graph is not None else glob.build(self.assets)

    @classmethod
    def collect(cls, ws: Workspace, max_assets: int = 20,
                extra_assets: Sequence["Asset"] = ()) -> "PlannerState":
        seen: Dict[Tuple[str, str], Asset] = {}
        denials: List[Tuple[str, str]] = []
        denial_keys = set()
        for row in ws.store.list_evidence(ws.scope.engagement_id):
            if row["method"] == "OOB":
                continue
            url = "%s://%s:%d%s" % (row["scheme"], row["host"], row["port"], row["raw_path"])
            netloc = urlsplit(url).netloc
            status = int(row["status"])
            if status in (401, 403) and url not in denial_keys:
                denial_keys.add(url)
                denials.append((netloc, url))
            params = tuple(str(p[0]) for p in json.loads(row["query_json"] or "[]"))
            try:
                hdrs = {str(k).lower(): str(v) for k, v in
                        (json.loads(row["headers_json"] or "[]") or [])}
            except (TypeError, ValueError):
                hdrs = {}
            body_params = tuple(f for f in
                                (hdrs.get("x-pta-body-fields") or "").split(",") if f)
            key = (row["method"], url)
            if key in seen:
                seen[key].hits += 1
                if body_params and not seen[key].body_params:
                    seen[key].body_params = body_params
                continue
            identity = row["identity"] or "none"
            body = b""
            ctype = row["content_type"] or ""
            if "json" in ctype.lower():
                # 只有 JSON 才值得读：HTML 里的 data-user-id 之类不算引用
                try:
                    blob = ws.cas.get(row["body_sha256"])
                except Exception:                      # 正文丢失不影响其余事实
                    blob = b""
                if blob and len(blob) <= glob.MAX_REF_BODY:
                    body = blob
            seen[key] = Asset(url=url, method=row["method"], params=params,
                              status=status, content_type=row["content_type"],
                              identity="none" if identity in ("", "none") else identity,
                              body_params=body_params, body=body)
        # 浏览器抓到的接口并进来。它们的 URL 带 query 值，而证据表里的 raw_path
        # 不带——同一个接口会在两边各有一条。按「去掉 query 后相同」合并，
        # 并让带值的那条胜出：候选命令要能直接打，就不能是 `?id=`。
        #
        # 比较用 graph.host_key + path：证据表的 URL 一律带端口（`:80`），
        # 浏览器抓到的是页面里写的那样（往往不带），字符串直接比会对不上。
        for extra in extra_assets:
            base = extra.url.split("?")[0]
            base_host = glob.host_key(base)
            base_path = urlsplit(base).path.rstrip("/") or "/"
            dup = None
            for k in list(seen):
                raw = k[1].split("?")[0]
                if k[0] != extra.method:
                    continue
                if glob.host_key(raw) != base_host:
                    continue
                if (urlsplit(raw).path.rstrip("/") or "/") != base_path:
                    continue
                dup = k
                break
            if dup is None:
                seen[(extra.method, extra.url)] = extra
                continue
            old = seen.pop(dup)
            seen[(extra.method, extra.url)] = Asset(
                url=extra.url, method=extra.method,
                params=extra.params or old.params,
                status=extra.status or old.status,
                content_type=extra.content_type or old.content_type,
                hits=old.hits + extra.hits,
                identity=old.identity if old.identity != "none" else extra.identity,
                body_params=extra.body_params or old.body_params,
                body=extra.body or old.body)
        assets = sorted(seen.values(), key=lambda a: -a.hits)[:max_assets]
        findings = [{"template_id": r["template_id"], "status": r["status"],
                     "confidence": round(float(r["confidence"]), 3), "title": r["title"]}
                    for r in ws.store.list_findings(ws.scope.engagement_id)]

        templates = [{"id": t["id"], "title": t["title"], "level": t["side_effect_level"],
                      "oracle": t["oracle"]["name"],
                      "param_hint": [p.get("name_hint") for p in t.get("preconditions", [])
                                     if p.get("kind") == "param_present"]}
                     for t in vhx.TEMPLATES]
        return cls(ws.scope.engagement_id, ws.scope.domains, assets, findings,
                   ws.budget.snapshot(), templates, denials)

    def deny_url(self, netloc: str, exclude_url: str = "") -> Optional[str]:
        """同一主机上已知会拒绝未授权访问的接口，用作拒绝模板。"""
        exclude = exclude_url.split("?", 1)[0].rstrip("/").lower()
        fallback = None
        for host, url in self.denials:
            if host != netloc:
                continue
            if url.split("?", 1)[0].rstrip("/").lower() == exclude:
                continue
            if fallback is None:
                fallback = url
        return fallback

    def compact(self, assets: Optional[Sequence[Asset]] = None) -> Dict[str, Any]:
        assets = list(self.assets if assets is None else assets)
        return {"engagement": self.engagement_id, "domains": list(self.domains),
                "budget": self.budget, "assets": [a.to_json() for a in assets],
                "graph": self.graph.to_json(),
                "findings": self.findings[:10], "templates": self.templates,
                "rule_candidates": [c.to_json() for c in
                                    _rule_candidates(assets, self.denials, 5)]}

    def prompt_payload(self) -> str:
        """硬上限：超了就砍资产，不砍模板（模板是合法性约束）。"""
        assets = list(self.assets)
        while True:
            state = self.compact(assets)
            text = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
            if len(text) <= MAX_PROMPT_CHARS or len(assets) <= 3:
                return text
            assets = assets[:max(3, len(assets) // 2)]


# ---------- 本地规则：降级链最后一级 ----------
_PARAM_RULES: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"^(id|uid|user_?id|order_?id|account_?id|pid|oid)$", re.I),
     "idor-object-ref", 0.75),
    (re.compile(r"(url|uri|target|redirect|next|image|img|webhook|callback|proxy)$", re.I),
     "ssrf-outbound", 0.65),
    # URL 类参数再排一次"打内网服务"：回连只能证明目标能出网，证明不了它能进内网，
    # 而内网服务（元数据/Docker/etcd）的指纹是最硬的证据。放在 oob 之后，成本更低。
    (re.compile(r"(url|uri|target|dest|next|link|image|img|webhook|callback|proxy|fetch)$", re.I),
     "ssrf-internal-service", 0.55),
    (re.compile(r"^(q|s|search|query|keyword|sort|order|filter|name|title)$", re.I),
     "sqli-error-boolean", 0.55),
    # 同一个参数再排一次布尔盲注：报错型靠"页面崩了"，布尔型靠"结果集变了"，
    # 服务端把异常吃掉（统一 500 页/WAF 静默）时只剩后者能判，成本是 3 次请求。
    (re.compile(r"^(q|s|search|query|keyword|sort|order|filter|name|title)$", re.I),
     "sqli-boolean-blind", 0.50),
]

# 请求体字段的规则表。只对 harvest 采到的字段名生效——这些字段是页面自己写进
# body 的，说明后端真的认它们；我们凭空猜 `{"role": "admin"}` 服务端多半直接忽略。
# 权重比 query 低半档：字段存在不等于接口会在意它，还得靠回读确认。
_BODY_RULES: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"^(role|roles|is_?admin|admin|superuser|user_?type|account_?type"
                r"|privilege|privileges|permissions?|scope|tier|plan)$", re.I),
     "mass-assignment-privilege", 0.72),
    (re.compile(r"^(name|title|description|nickname|display_?name|email|phone)$", re.I),
     "idor-write-object", 0.58),
]

# 像「接口」而不是「页面」的路径：这类端点通常有身份与权限概念，值得复核一次无凭据访问。
_AUTHZ_PATH = re.compile(
    r"/(api|rest|graphql|internal|backend|account|admin|me|profile|v[0-9]+)(/|$|\.json$)", re.I)

_AUTHZ_PRIORITY_WITH_CONTROL = 0.78
_AUTHZ_PRIORITY_WITHOUT_CONTROL = 0.70

# "会改状态"的方法。只有它们才谈得上写入型越权；
# GET 上的同名字段（`?name=`）是查询条件，不是可写字段。
WRITE_METHODS = ("POST", "PUT", "PATCH")
_WRITE_PRIORITY = 0.60

# 图候选最多占几个位子。
#
# 图候选的优先级刻意压在规则候选之后（见 graph 模块开头：规则命中的证据更硬），
# 但 discover 一次能收上百个资产、候选池只有 30 个位子，纯按优先级排的话
# 图外推永远排不进去——特性等于没写。所以给它留几个固定的尾部位子，
# 从最低优先级的规则候选那里换过来。默认 4 个：够让人看见"还能往哪打一步"，
# 又不至于把规则候选挤掉。
MAX_GRAPH_SLOTS = 4


def _write_candidates(asset: Asset) -> List[Candidate]:
    """harvest 看到页面自己用写方法打过的接口，就值得试一次写入越权。

    为什么需要这条：`_BODY_RULES` 只在"看到请求体字段"时才出候选，而很多页面
    的写请求体是空的（按钮点了才填），或者字段名不在规则表里。但"页面用 POST/PUT
    打过这个 URL"本身就是一个强信号：这个端点接受写。
    代价是一次 8 请求内的试探，被判否也无害（400/422 会立刻停）。
    """
    if asset.method.upper() not in WRITE_METHODS:
        return []
    if asset.body_params:
        return []                     # 已经有具体字段，交给 _BODY_RULES，别重复出候选
    path = urlsplit(asset.url).path or "/"
    ctype = (asset.content_type or "").lower()
    if not (_AUTHZ_PATH.search(path) or "json" in ctype):
        return []
    return [Candidate(
        template_id="idor-write-object", url=asset.url, param_path="body:*",
        method=asset.method, priority=_WRITE_PRIORITY,
        rationale="页面自己用 %s 打过 %s（harvest），但没暴露请求体字段："
                  "按通用写操作试一次（标记写到 name 上）" % (asset.method, path))]


def _authz_candidate(asset: Asset, denials: Sequence[Tuple[str, str]]) -> Optional[Candidate]:
    """只生成「值得复核」的候选：已用某个身份读到 200 数据，且路径像接口。"""
    if asset.method.upper() not in ("GET", "HEAD"):
        return None
    if asset.status != 200:
        return None
    if asset.identity in ("", "none"):
        return None                       # 没有任何身份能读，谈不缺失授权
    path = urlsplit(asset.url).path or "/"
    ctype = (asset.content_type or "").lower()
    if not (_AUTHZ_PATH.search(path) or "json" in ctype):
        return None
    netloc = urlsplit(asset.url).netloc
    control = None
    for host, url in denials:
        if host != netloc:
            continue
        if url.split("?", 1)[0].rstrip("/").lower() == asset.url.split("?", 1)[0].rstrip("/").lower():
            continue
        control = url
        break
    note = "「%s」用身份 %s 读到了数据，复核无凭据请求是否同样放行" % (path, asset.identity)
    if control:
        note += "；拒绝模板取同主机已知 401/403：%s" % control
        priority = _AUTHZ_PRIORITY_WITH_CONTROL
    else:
        note += "；同主机暂无 401/403 证据，无拒绝模板（置信度上限 0.88）"
        priority = _AUTHZ_PRIORITY_WITHOUT_CONTROL
    return Candidate(template_id="authz-missing-endpoint", url=asset.url,
                     identity_baseline=asset.identity, identity_probe="none",
                     method=asset.method, priority=priority, rationale=note,
                     control_url=control)


def _rule_candidates(assets: Sequence[Asset], denials: Sequence[Tuple[str, str]],
                     max_candidates: int = MAX_CANDIDATES,
                     graph: Optional["glob.Graph"] = None,
                     graph_slots: int = MAX_GRAPH_SLOTS) -> List[Candidate]:
    out: List[Candidate] = []
    for asset in assets:
        for param in asset.params:
            for pattern, template_id, weight in _PARAM_RULES:
                if not pattern.search(param):
                    continue
                out.append(Candidate(template_id=template_id, url=asset.url,
                                     param_path="query:%s" % param, priority=weight,
                                     rationale="参数名 %s 命中规则" % param))
        for field in asset.body_params:
            for pattern, template_id, weight in _BODY_RULES:
                if not pattern.search(field):
                    continue
                if template_id in ("idor-write-object", "mass-assignment-privilege") \
                        and asset.method.upper() not in WRITE_METHODS:
                    # 字段名出现在 GET 上说明它是查询条件：改它不会写到任何对象上
                    continue
                # mass-assignment 的载荷是"多加一个字段"，参数路径固定 body:*；
                # idor-write-object 则是改写已有字段，要指名道姓。
                path = "body:*" if template_id == "mass-assignment-privilege" \
                    else "body:%s" % field
                out.append(Candidate(
                    template_id=template_id, url=asset.url, param_path=path,
                    method=asset.method, priority=weight,
                    rationale="页面自己在 %s 的请求体里发了字段 %s（harvest）"
                              % (asset.url.split("?")[0], field)))
        if not asset.params and not asset.body_params:
            out.append(Candidate(template_id="info-disclosure-artifact", url=asset.url,
                                 priority=0.3, rationale="无参端点，先查敏感产物"))
        authz = _authz_candidate(asset, denials)
        if authz is not None:
            out.append(authz)
        out.extend(_write_candidates(asset))
    # 图展开的候选优先级都在 0.62 以下，排在规则候选之后：规则命中的证据更硬
    out.extend(glob.candidates(graph))
    out.sort(key=lambda c: -c.priority)
    if len(out) <= max_candidates:
        return out
    kept = out[:max_candidates]
    # 给图候选留几个尾部位子：从尾部换掉优先级最低的规则候选，
    # 而不是让"上百个规则候选"把外推整段挤没。
    if graph_slots > 0 and max_candidates > graph_slots:
        have = sum(1 for c in kept if c.source == "graph")
        if have < graph_slots:
            spare = [c for c in out[max_candidates:] if c.source == "graph"]
            take = spare[:graph_slots - have]
            if take:
                kept = kept[:max_candidates - len(take)] + take
                kept.sort(key=lambda c: -c.priority)
    return kept


def heuristic_candidates(state: PlannerState, max_candidates: int = MAX_CANDIDATES,
                         graph_slots: int = MAX_GRAPH_SLOTS) -> List[Candidate]:
    return _rule_candidates(state.assets, state.denials, max_candidates, state.graph,
                            graph_slots=graph_slots)


class Planner:
    def __init__(self, ws: Workspace, model: Optional[ModelClient] = None,
                 max_candidates: int = MAX_CANDIDATES, on_event=None):
        self.ws = ws
        self.model = model
        self.max_candidates = max_candidates
        self.on_event = on_event
        self.last_calls: List[Dict[str, Any]] = []

    def plan(self, state: Optional[PlannerState] = None) -> Plan:
        state = state or PlannerState.collect(self.ws)
        if self.model is None:
            plan = self._heuristic(state, note="未配置模型，使用本地规则")
        else:
            try:
                plan = self._model_plan(state)
            except (ModelUnavailable, PlannerBlocked, PtaError) as exc:
                plan = self._heuristic(state, note="模型不可用，降级本地规则")
                plan.degraded = True
                plan.notes = "%s（%s）" % (plan.notes, exc)
                if self.on_event:
                    self.on_event({"type": "planner_degraded", "reason": str(exc)})
        return self._filter(plan)

    # ---------- 模型路径 ----------
    def _model_plan(self, state: PlannerState) -> Plan:
        system = build_system(state.engagement_id, state.domains)
        guard = GuardedModel(self.model, on_event=self.on_event)
        payload = guard.ask_json(system, state.prompt_payload(), CANDIDATE_SCHEMA)
        self.last_calls = list(guard.log)
        cands = []
        for raw in payload.get("candidates", []):
            cands.append(Candidate(
                template_id=str(raw["template_id"]), url=str(raw["url"]),
                param_path=raw.get("param_path"),
                identity_baseline=raw.get("identity_baseline") or "none",
                identity_probe=raw.get("identity_probe") or "none",
                method=(raw.get("method") or "GET").upper(),
                priority=float(raw.get("priority", 0.5)),
                rationale=str(raw.get("rationale") or "")[:300],
                control_url=raw.get("control_url") or None,
                source="model",
            ))
        return Plan(candidates=cands, notes=str(payload.get("notes") or "")[:500],
                    source="model")

    def _heuristic(self, state: PlannerState, note: str) -> Plan:
        return Plan(candidates=heuristic_candidates(state, self.max_candidates),
                    notes=note, source="heuristic")

    # ---------- 业务校验 ----------
    def _filter(self, plan: Plan) -> Plan:
        known = {t["id"] for t in vhx.TEMPLATES}
        accepted: List[Candidate] = []
        seen = set()
        for cand in plan.candidates:
            self._clean_control(cand)
            reject = self._reject_reason(cand, known)
            if reject:
                plan.rejected.append({"template_id": cand.template_id, "url": cand.url,
                                      "reason": reject})
                continue
            if cand.key() in seen:
                plan.rejected.append({"template_id": cand.template_id, "url": cand.url,
                                      "reason": "duplicate"})
                continue
            seen.add(cand.key())
            accepted.append(cand)
        accepted.sort(key=lambda c: -c.priority)
        plan.candidates = accepted[:self.max_candidates]
        if not plan.candidates and plan.blocked_reason is None and plan.rejected:
            plan.notes = (plan.notes + " 全部候选被校验拒绝").strip()
        return plan

    def _clean_control(self, cand: Candidate) -> None:
        """拒绝模板只是额外证据，坏掉就丢掉它，不因此杀掉候选。"""
        if not cand.control_url:
            return
        reason = ""
        try:
            self.ws.scope.check_url(cand.control_url)
        except PtaError as exc:
            reason = "拒绝模板越界（%s）" % exc
        else:
            if urlsplit(cand.control_url).netloc != urlsplit(cand.url).netloc:
                reason = "拒绝模板与目标不同主机"
            elif (cand.control_url.split("?", 1)[0].rstrip("/").lower()
                  == cand.url.split("?", 1)[0].rstrip("/").lower()):
                reason = "拒绝模板与目标同一路径，无法区分"
        if reason:
            cand.control_url = None
            cand.rationale = ("%s；已丢弃%s" % (cand.rationale, reason))[:300]

    def _reject_reason(self, cand: Candidate, known: set) -> Optional[str]:
        if cand.template_id not in known:
            return "unknown_template"
        if cand.param_path:
            if ":" not in cand.param_path:
                return "param_path 缺少 location 前缀"
            loc = cand.param_path.split(":", 1)[0]
            if loc not in ("query", "body", "header"):
                return "param_path location 非法"
        try:
            self.ws.scope.check_url(cand.url)
        except ScopeViolation as exc:
            return "out_of_scope:%s" % exc
        except PtaError as exc:
            return "invalid_url:%s" % exc
        if self._already_found(cand):
            return "already_found"
        return None

    def _already_found(self, cand: Candidate) -> bool:
        base = cand.url.split("?", 1)[0].rstrip("/").lower()
        for row in self.ws.store.list_findings(self.ws.scope.engagement_id):
            if row["template_id"] != cand.template_id:
                continue
            if row["status"] not in ("confirmed", "hypothesis"):
                continue
            ev_ids = json.loads(row["evidence_ids_json"] or "[]")
            for ev_id in ev_ids:
                erow = self.ws.store.get_evidence_row(ev_id)
                if erow is None:
                    continue
                url = "%s://%s:%d%s" % (erow["scheme"], erow["host"], erow["port"],
                                        erow["raw_path"])
                if url.rstrip("/").lower() == base:
                    return True
        return False


# ---------- 编排：plan → execute → 回灌 ----------
@dataclass
class RoundRecord:
    round_index: int
    plan: Plan
    findings: List[Finding] = field(default_factory=list)
    requests: int = 0

    def to_json(self) -> Dict[str, Any]:
        return {"round": self.round_index, "plan": self.plan.to_json(),
                "requests": self.requests,
                "findings": [f.to_json() for f in self.findings]}


def _node_id(kind: str, key: str) -> str:
    return "%s-%s" % (kind, hashlib.sha256(key.encode("utf-8")).hexdigest()[:12])


class EngagementRunner:
    """一次任务的完整循环。人工审批点在这里表现为暂停而不是继续猜。

    并发只发生在**同一轮的候选之间**，并且有三条边界：

    1. 有上限（`workers`，默认 3）：手上有几台机器就打多快，这是运维边界；
    2. 按批提交：一批跑完再提交下一批，审批一暂停就不会再多派活；
    3. 预算与限速仍由 `Budget` 统一收口（占号在锁内、等待在锁外）。

    每轮、每个资产、每个候选都会落一个 PTT 节点，回答"这轮为什么停、
    哪个候选还没跑"——这是串行 for 循环给不了的东西。
    """

    def __init__(self, ws: Workspace, planner: Planner, max_rounds: int = 3,
                 max_candidates: int = MAX_CANDIDATES, on_event=None, critic=None,
                 workers: int = 3, resume: bool = False):
        self.ws = ws
        self.planner = planner
        self.max_rounds = max_rounds
        self.max_candidates = max_candidates
        self.on_event = on_event
        self.critic = critic
        self.workers = max(1, int(workers))
        self.executor = Executor(ws.probe, ws.store, ws.scope.engagement_id,
                                 browser=getattr(ws, "browser", None))
        self.rounds: List[RoundRecord] = []
        self.critiques: List[Dict[str, Any]] = []
        self._critic_lock = threading.Lock()
        self._templates: Dict[str, "vhx.Template"] = {}
        self.run_key = "run-%s" % hashlib.sha256(
            ("%s|%d" % (ws.scope.engagement_id, id(self))).encode()).hexdigest()[:8]
        self.resume = bool(resume)
        self.resumed_keys: set = set()
        self.skipped: List[Dict[str, Any]] = []
        self.start_round = 0
        self.prior: Dict[str, Any] = {"candidates": 0, "confirmed": 0, "requests": 0}
        if self.resume:
            self._restore()

    # ---------- PTT ----------
    def _restore(self) -> None:
        """读上一轮的 PTT，算出"从第几轮继续、哪些候选不用再跑"。

        只认 `done:*`：

        - `running` 说明进程是在那一发上被杀的——既没结论也没证据，重跑是对的；
        - `done:pending_approval` 是"等你批"，批完就该接着跑，不算完成；
        - `skipped:budget` 更不算——那是没跑。

        跳过时不重写节点：`done:confirmed` 是上一轮的结论，覆盖成 `skipped:resumed`
        会把账弄丢（`put_node` 是 INSERT OR REPLACE）。跳过的候选只记在 summary 里。
        """
        eng = self.ws.scope.engagement_id
        done: set = set()
        prior = {"candidates": 0, "confirmed": 0, "requests": 0}
        max_round = -1
        round_seen = 0
        for row in self.ws.store.nodes(eng):
            try:
                detail = json.loads(row["detail_json"] or "{}")
            except ValueError:
                detail = {}
            if row["kind"] == "candidate":
                prior["candidates"] += 1
                prior["requests"] += int(detail.get("requests") or 0)
                status = row["status"] or ""
                if status.startswith("done:") and status != "done:pending_approval":
                    done.add(row["node_id"])
                    if status == "done:confirmed":
                        prior["confirmed"] += 1
            elif row["kind"] == "round":
                round_seen += 1
                idx = detail.get("round")
                if isinstance(idx, int):
                    max_round = max(max_round, idx)
        if max_round < 0 and round_seen:
            # 升级前落的节点没有 round 字段：退回按节点数推断
            max_round = round_seen - 1
        self.resumed_keys = done
        self.start_round = max_round + 1
        self.prior = prior
        if self.on_event:
            self.on_event({"type": "resume", "start_round": self.start_round,
                           "skipped": len(done), "prior": prior})

    def _node(self, kind: str, key: str, parent: Optional[str], label: str,
              status: str, detail: Optional[Dict[str, Any]] = None) -> str:
        nid = _node_id(kind, key)
        self.ws.store.put_node(self.ws.scope.engagement_id, nid, parent, kind, label,
                               status, detail)
        return nid

    def _template(self, template_id: str) -> "vhx.Template":
        # 模板加载放主线程并缓存：vhx.load 会做 lint，重复做既浪费也可能踩到共享状态。
        # 走覆盖层，让 calibrate --apply 的阈值在 auto 里也生效（模板本身不动）。
        tpl = self._templates.get(template_id)
        if tpl is None:
            from . import overrides as _ov
            try:
                tpl = _ov.load_template(self.ws, template_id)[0]
            except KeyError:
                raise KeyError("unknown_template: %s" % template_id)
            self._templates[template_id] = tpl
        return tpl

    def _exhausted(self) -> bool:
        return self.ws.budget.used >= self.ws.budget.max_requests

    def _one(self, cand, round_id: str, host_id: str) -> Optional[Finding]:
        key = "%s|%s|%s" % (cand.template_id, cand.url, cand.param_path or "")
        if self.resume and _node_id("candidate", key) in self.resumed_keys:
            # 上一轮已经有结论：不再发包，也不改它的 PTT 节点。
            self.skipped.append({"template_id": cand.template_id, "url": cand.url,
                                 "param_path": cand.param_path or "",
                                 "node_id": _node_id("candidate", key)})
            return None
        node = self._node("candidate", key, host_id,
                          "%s @ %s" % (cand.template_id, urlsplit(cand.url).path or "/"),
                          "running", {"priority": cand.priority, "key": key})
        if self._exhausted():
            self._node("candidate", key, host_id,
                       "%s @ %s" % (cand.template_id, cand.url), "skipped:budget")
            raise RuntimeError("budget")
        f = self.executor.run(self._template(cand.template_id), cand.to_target())
        if self.critic is not None:
            crit = self.critic.review_finding(f)
            with self._critic_lock:
                self.critiques.append(crit.to_json())
            if crit.status == "vetoed":
                f.status = "refuted"
        self._node("candidate", key, host_id,
                   "%s @ %s" % (cand.template_id, urlsplit(cand.url).path or "/"),
                   "done:%s" % f.status,
                   {"confidence": f.confidence, "stop_reason": f.stop_reason,
                    "requests": f.requests_used, "key": key})
        return f

    def run(self) -> Dict[str, Any]:
        stop_reason = ""
        paused = ""
        pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="pta-run")
        try:
            for i in range(self.start_round, self.start_round + self.max_rounds):
                if self._exhausted():
                    stop_reason = "budget_exhausted"
                    break
                plan = self.planner.plan()
                record = RoundRecord(round_index=i, plan=plan)
                round_id = self._node("round", "%s:%d" % (self.ws.scope.engagement_id, i), None,
                                      "第 %d 轮（候选 %d）" % (i + 1, len(plan.candidates)),
                                      "running", {"round": i, "resume": self.resume})
                if not plan.candidates:
                    stop_reason = plan.notes or "no_candidates"
                    self._node("round", "%s:%d" % (self.ws.scope.engagement_id, i), None,
                               "第 %d 轮（候选 0）" % (i + 1), "done:no_candidates",
                               {"round": i, "resume": self.resume})
                    self.rounds.append(record)
                    break

                host_ids: Dict[str, str] = {}
                for start in range(0, len(plan.candidates), self.workers):
                    batch = plan.candidates[start:start + self.workers]
                    futures = []
                    for cand in batch:
                        host = urlsplit(cand.url).netloc
                        hid = host_ids.get(host)
                        if hid is None:
                            hid = host_ids[host] = self._node(
                                "asset", host, round_id, host, "running",
                                {"candidates": sum(1 for c in plan.candidates
                                                   if urlsplit(c.url).netloc == host)})
                        futures.append((cand, host, pool.submit(self._one, cand, round_id, hid)))
                    for cand, host, fut in futures:
                        try:
                            f = fut.result()
                        except RuntimeError:
                            stop_reason = "budget_exhausted"
                            continue
                        if f is None:      # 续跑时跳过：上一轮已有结论
                            continue
                        record.findings.append(f)
                        record.requests += f.requests_used
                        if f.stop_reason.startswith("pending_approval"):
                            paused = f.stop_reason
                    if paused or self._exhausted():
                        if self._exhausted():
                            stop_reason = "budget_exhausted"
                        break

                for host, hid in host_ids.items():
                    done = [f for f in record.findings]
                    self._node("asset", host, round_id, host,
                               "paused" if paused else "done",
                               {"findings": len(done)})
                self._node("round", "%s:%d" % (self.ws.scope.engagement_id, i), None,
                           "第 %d 轮（候选 %d）" % (i + 1, len(plan.candidates)),
                           "paused" if paused else ("done:%s" % (stop_reason or "ok")),
                           {"requests": record.requests, "findings": len(record.findings),
                            "round": i, "resume": self.resume,
                            "skipped_resumed": len(self.skipped)})
                self.rounds.append(record)

                if paused:
                    stop_reason = paused
                    break
                if self.on_event:
                    self.on_event({"type": "round_done", "round": i,
                                   "findings": [f.to_json() for f in record.findings]})
                if self._exhausted():
                    stop_reason = "budget_exhausted"
                    break
        finally:
            pool.shutdown(wait=True)

        summary = self.summary()
        summary["stop_reason"] = stop_reason or "max_rounds"
        summary["workers"] = self.workers
        summary["run_key"] = self.run_key
        nodes = self.ws.store.nodes(self.ws.scope.engagement_id)
        by_kind: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for n in nodes:
            by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
            by_status[n["status"]] = by_status.get(n["status"], 0) + 1
        summary["ptt"] = {"nodes": len(nodes), "by_kind": by_kind, "by_status": by_status}
        return summary

    def summary(self) -> Dict[str, Any]:
        findings = [f for r in self.rounds for f in r.findings]
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.status] = counts.get(f.status, 0) + 1
        return {"engagement_id": self.ws.scope.engagement_id,
                "rounds": [r.to_json() for r in self.rounds],
                "requests": sum(r.requests for r in self.rounds),
                "budget": self.ws.budget.snapshot(),
                "counts": counts,
                "critiques": self.critiques,
                "findings": [f.to_json() for f in findings],
                "resume": {"enabled": self.resume, "start_round": self.start_round,
                           "skipped": list(self.skipped), "prior": dict(self.prior)}}
