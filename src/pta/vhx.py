"""vhx 模板：加载期 lint + 与 oracle 的强绑定。

模板只描述"怎么试"和"怎么判定"，不包含任何目标地址。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from . import payloads
from .errors import VhxInvalid
from .oracles import ORACLE_REGISTRY

ACTIONS = frozenset({
    "http_request", "mutate_param", "swap_identity", "browser_nav", "replay",
    "diff_response", "timing_sample", "oob_arm", "oob_check", "decode_token",
    "concurrent_burst", "batch_sweep",
})
PRECONDITIONS = frozenset({"endpoint_exists", "identity_available", "asset_type", "param_present"})
LEVELS = ("L0", "L1", "L2", "L3")

REQUIRED_FIELDS = (
    "vhx_version", "id", "title", "category", "cwe", "side_effect_level",
    "requires_approval", "preconditions", "surface", "probe", "oracle",
    "evidence_required", "counter_evidence", "fp_traps", "stop_conditions",
    "budget", "mutator_hints", "report_note",
)


@dataclass
class Template:
    raw: Dict[str, Any]

    def __getattr__(self, item: str) -> Any:
        try:
            return self.raw[item]
        except KeyError:
            raise AttributeError(item)

    @property
    def id(self) -> str:
        return self.raw["id"]

    @property
    def level(self) -> str:
        return self.raw["side_effect_level"]


def lint(raw: Dict[str, Any], scope_budget: int = 9000) -> List[str]:
    errs: List[str] = []
    # 多角色模板（布尔盲注这类）把注入计划写在 probe.role_hints 里，
    # 一个基线之外要打"真/假"两份载荷，mutator_hints 的"逐个试"语义不适用。
    has_role_hints = bool((raw.get("probe") or {}).get("role_hints"))
    for f in REQUIRED_FIELDS:
        if f == "mutator_hints" and has_role_hints:
            continue
        if f not in raw:
            errs.append("缺少字段 %s" % f)
    if errs:
        return errs

    if raw["side_effect_level"] not in LEVELS:
        errs.append("side_effect_level 非法：%s" % raw["side_effect_level"])

    action = raw["probe"].get("action")
    if action not in ACTIONS:
        errs.append("action 不在词表：%s" % action)

    for pc in raw["preconditions"]:
        if pc.get("kind") not in PRECONDITIONS:
            errs.append("precondition kind 不可求值：%s" % pc.get("kind"))

    o = raw["oracle"]
    if o.get("name") not in ORACLE_REGISTRY:
        errs.append("oracle 未注册：%s" % o.get("name"))
    else:
        try:
            ORACLE_REGISTRY[o["name"]].Args(**(o.get("args") or {}))
        except TypeError as exc:
            errs.append("oracle args 非法：%s" % exc)

    if raw["requires_approval"] and raw["side_effect_level"] in ("L0", "L1"):
        errs.append("L0/L1 不应要求审批（会拖慢正常流程）")
    if raw["side_effect_level"] in ("L2", "L3") and not raw["requires_approval"]:
        errs.append("L2/L3 必须 requires_approval=true")

    min_req = int(raw["budget"].get("min_requests", 0))
    max_req = int(raw["budget"].get("max_requests", 0))
    # 自带执行/回连标记的模板不需要额外对照请求；其余模板至少要有 baseline + probe 两次
    _self_evident = ("execution_marker:", "oob_token:", "callback:")
    needs_control = not any(str(e).startswith(_self_evident)
                            for e in raw.get("evidence_required", ()))
    if min_req < (2 if needs_control else 1):
        errs.append("budget.min_requests 至少 %d（%s）" % (
            2 if needs_control else 1,
            "需要对照请求" if needs_control else "已有执行标记，无需对照"))
    if max_req > max(10, int(scope_budget * 0.2)):
        errs.append("budget 超过 scope 的 20%%：%d" % max_req)
    if min_req > max_req:
        errs.append("min_requests > max_requests")

    if len(raw["counter_evidence"]) < 2:
        errs.append("counter_evidence 至少 2 条")

    ev = " ".join(raw["evidence_required"])
    if "request_canonical" not in ev:
        errs.append("evidence_required 缺少 request_canonical*")
    if "response_sha256" not in ev:
        errs.append("evidence_required 缺少 response_sha256*")

    for h in raw.get("mutator_hints", []):
        if h.get("payload_class") and h["payload_class"] not in payloads.REGISTRY:
            errs.append("payload_class 未注册：%s" % h["payload_class"])
    return errs


def load(raw: Dict[str, Any], scope_budget: int = 9000) -> Template:
    errs = lint(raw, scope_budget)
    if errs:
        raise VhxInvalid("%s: %s" % (raw.get("id", "<no-id>"), "; ".join(errs)))
    return Template(raw)


def load_dir(path: str, scope_budget: int = 9000) -> List[Template]:
    out: List[Template] = []
    for name in sorted(os.listdir(path)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(path, name), "r", encoding="utf-8") as fh:
            out.append(load(json.load(fh), scope_budget))
    return out


TEMPLATES: List[Dict[str, Any]] = [
    {
        "vhx_version": "1.0",
        "id": "idor-object-ref",
        "title": "对象引用越权（IDOR）",
        "category": "broken-access-control",
        "cwe": "CWE-639",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "identity_available", "role": "probe"},
            {"kind": "param_present", "location": "query|path", "name_hint": "id"},
        ],
        "surface": {"methods": ["GET"], "auth": "both"},
        "probe": {"action": "swap_identity", "decoy": True,
                  "sequence": ["http_request", "swap_identity", "http_request"]},
        "oracle": {"name": "differential_object_access", "args": {"min_similarity": 0.92}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "identity:baseline", "identity:probe", "status:probe",
        ],
        "counter_evidence": [
            "probe 返回 401/403", "probe 返回 404", "probe 内容与 baseline 差异大（similarity<0.6）",
            "probe 返回的是登录页/错误页模板",
            "不存在的对象（decoy）也返回同样内容——响应与对象 id 无关",
        ],
        "fp_traps": ["两个身份相同", "baseline 本身已越权", "响应被 WAF 统一替换"],
        "stop_conditions": ["连续 3 次 403", "相似度 < 0.6 连续 5 次"],
        "budget": {"min_requests": 3, "max_requests": 12},
        "mutator_hints": [],
        "report_note": "必须同时给出 baseline 与 probe 两条证据链接，以及越权后可读字段清单。",
    },
    {
        "vhx_version": "1.0",
        "id": "idor-batch-sweep",
        "title": "批量对象越权（相邻 id 连续可读）",
        "category": "broken-access-control",
        "cwe": "CWE-639",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "identity_available", "role": "probe"},
            {"kind": "param_present", "location": "query|path", "name_hint": "id"},
        ],
        "surface": {"methods": ["GET"], "auth": "required"},
        "probe": {"action": "http_request", "decoy": True,
                  "batch": {"count": 20, "step": 1},
                  "sequence": ["http_request", "batch_sweep", "diff_response"]},
        "oracle": {"name": "batch_unauthorized_read", "args": {}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "identity:probe", "status:probe",
        ],
        "counter_evidence": [
            "相邻对象全部 401/403/404——对象级授权在起作用",
            "不存在的对象（decoy）也返回同样内容——响应与对象 id 无关",
            "几个不同 id 的响应几乎一样——读到的不是各自的对象",
            "id 是 uuid 形态、没有相邻可枚举的对象",
        ],
        "fp_traps": [
            "相邻 id 本来就属于同一个公开资源（商品目录、文章列表）",
            "接口返回的是全量列表而不是单个对象",
            "分页参数与对象 id 同名，扫出来的其实是页码",
        ],
        "stop_conditions": ["连续 3 次 401/403", "预算耗尽"],
        "budget": {"min_requests": 3, "max_requests": 60},
        "mutator_hints": [],
        "report_note": ("必须给出「可读/总数」与状态分布，并写清这些 id 是当前身份"
                        "不具备归属的对象；单个对象可读不算结论。"),
    },
    {
        "vhx_version": "1.0",
        "id": "authz-missing-endpoint",
        "title": "接口缺失授权（无凭据即可读）",
        "category": "broken-access-control",
        "cwe": "CWE-862",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
        ],
        "surface": {"methods": ["GET"], "auth": "required"},
        "probe": {
            "action": "swap_identity",
            "sequence": ["http_request", "swap_identity", "diff_response"],
            "control": {
                "required": False,
                "hint": "同一主机上已知需要登录的兄弟接口：用它取一次真实的 401/403 当拒绝模板",
            },
        },
        "oracle": {
            "name": "authz_template_diff",
            "args": {"min_similarity_data": 0.90, "min_similarity_deny": 0.85},
        },
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "identity:probe", "status:probe",
        ],
        "counter_evidence": [
            "无凭据返回 401/403",
            "无凭据被 302/303 跳到登录页",
            "返回内容与拒绝模板等价（登录页 / 统一壳页）",
            "内容与授权视角差异过大（similarity<0.6）",
        ],
        "fp_traps": [
            "未登录即返回 SPA 壳页，内容看似完整",
            "CDN/缓存把授权响应回给了匿名请求",
            "两个观察用了同一身份",
        ],
        "stop_conditions": ["连续 3 次 401/403", "返回内容与拒绝模板等价"],
        "budget": {"min_requests": 2, "max_requests": 8},
        "mutator_hints": [],
        "report_note": "必须给出 baseline 与 probe 两条证据；有 control 证据时一并附上，说明拒绝模板从哪个接口取的。",
    },
    {
        "vhx_version": "1.0",
        "id": "info-disclosure-artifact",
        "title": "敏感构建产物/凭据文件暴露",
        "category": "information-disclosure",
        "cwe": "CWE-538",
        "side_effect_level": "L0",
        "requires_approval": False,
        "preconditions": [{"kind": "endpoint_exists", "path": "/"}],
        "surface": {"methods": ["GET"], "auth": "none"},
        "probe": {"action": "http_request", "sequence": ["http_request", "diff_response"]},
        "oracle": {"name": "file_signature_match", "args": {"min_confidence": 0.85}},
        "evidence_required": [
            "request_canonical:probe", "response_sha256:probe", "status:probe",
            "content_type:probe",
        ],
        "counter_evidence": [
            "返回 HTML 首页（SPA 回退）", "返回 JSON 错误体", "状态码 404/403",
            "内容与 base 页面完全一致",
        ],
        "fp_traps": ["CDN 统一 200 回退", "WAF 拦截页伪装成 200", "压缩/编码差异"],
        "stop_conditions": ["连续 2 次反特征命中", "站点根路径即 SPA 壳"],
        "budget": {"min_requests": 2, "max_requests": 10},
        "mutator_hints": [{"payload_class": "wellknown_path", "note": "/.git/HEAD 先试，再试 /.env"}],
        "report_note": "只报可验证的文件类型，禁止把 HTML 壳当泄露。",
    },
    {
        "vhx_version": "1.0",
        "id": "sqli-error-boolean",
        "title": "报错/布尔型 SQL 注入",
        "category": "injection",
        "cwe": "CWE-89",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "param_present", "location": "query", "name_hint": "id|q|search"},
        ],
        "surface": {"methods": ["GET"], "auth": "any"},
        "probe": {"action": "mutate_param", "sequence": ["http_request", "mutate_param", "diff_response"]},
        "oracle": {"name": "error_signature_match", "args": {"min_weight": 0.85}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe", "status:probe",
        ],
        "counter_evidence": [
            "baseline 已包含相同错误", "错误来自 WAF 自定义页", "probe 返回 400 且无 SQL 特征",
            "响应被统一重定向到登录页",
        ],
        "fp_traps": ["框架把异常渲染成统一 JSON", "错误页被缓存"],
        "stop_conditions": ["连续 5 次 403/429", "熔断打开"],
        "budget": {"min_requests": 3, "max_requests": 15},
        "mutator_hints": [
            {"payload_class": "syntax_break"},
            {"payload_class": "boolean_true"},
            {"payload_class": "boolean_false"},
        ],
        "report_note": "报错型只报签名命中；布尔型必须另有 boolean_response_split 佐证。",
    },
    {
        "vhx_version": "1.0",
        "id": "ssrf-outbound",
        "title": "服务端请求伪造（带外确认）",
        "category": "ssrf",
        "cwe": "CWE-918",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "param_present", "location": "query",
             "name_hint": "url|uri|target|redirect|image|webhook"}
        ],
        "surface": {"methods": ["GET", "POST"], "auth": "any"},
        "probe": {"action": "oob_arm",
                  "sequence": ["oob_arm", "mutate_param", "oob_check"]},
        "oracle": {"name": "oob_callback_received",
                   "args": {"min_callbacks": 1, "require_http": False}},
        "evidence_required": [
            "request_canonical:probe", "response_sha256:probe", "oob_token",
            "callback:source_ip", "callback:path"
        ],
        "counter_evidence": [
            "目标直接拒绝（400/403）且无回连", "回连来源是我方出口 IP（自触发）",
            "内网地址黑名单拦截", "仅 DNS 解析但无 HTTP 请求（可能是预检）"
        ],
        "fp_traps": ["代理/CDN 代为解析域名", "安全设备主动回连探测", "DNS 预取"],
        "stop_conditions": ["连续 2 次被 403 拦截", "回连全为自触发", "预算耗尽"],
        "budget": {"min_requests": 2, "max_requests": 8},
        "mutator_hints": [{"payload_class": "oob_url"}],
        "report_note": "必须给出回连时间、源 IP 与请求路径；只有 DNS 证据时降级为 hypothesis。",
    },
    {
        "vhx_version": "1.0",
        "id": "ssrf-internal-service",
        "title": "服务端请求伪造（打内网服务，看回显指纹）",
        "category": "ssrf",
        "cwe": "CWE-918",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "param_present", "location": "query",
             "name_hint": "url|uri|target|dest|next|link|image|fetch|proxy|callback|host"}
        ],
        "surface": {"methods": ["GET", "POST"], "auth": "any"},
        "probe": {"action": "http_request",
                  "baseline": {"required": True},
                  # 内网地址常常是不可达的（云元数据只在云上、docker 端口没开）：
                  # 10s 默认超时会让一次 SSRF 验证白等三次。
                  "timeout_s": 3,
                  "sequence": ["http_request", "mutate_param", "http_request", "diff_response"]},
        "oracle": {"name": "internal_service_fingerprint", "args": {"min_markers": 2}},
        "evidence_required": [
            "request_canonical:probe", "response_sha256:probe",
            "response_sha256:baseline", "status:probe"
        ],
        "counter_evidence": [
            "回显里没有内网服务特征（参数不在控制 URL / 响应被重写）",
            "基线本来就能看到同一服务（参数没起作用）",
            "只命中单个特征串，可能是页面里的通用词",
            "目标对私网地址做了黑名单（400/403）"
        ],
        "fp_traps": ["应用自己聚合第三方内容，页里本来就有这些词", "CDN/代理代为请求", "错误页复用了上游回显"],
        "stop_conditions": ["连续 2 次被 403 拦", "所有内网地址都超时", "预算耗尽"],
        "budget": {"min_requests": 2, "max_requests": 12},
        "mutator_hints": [
            {"payload_class": "internal_metadata_url", "param_path": "query:url"},
            {"payload_class": "internal_docker_url", "param_path": "query:url"},
            {"payload_class": "internal_etcd_url", "param_path": "query:url"}
        ],
        "report_note": "必须写清命中哪类内部服务与哪几个特征串；单特征命中降级为 hypothesis。",
    },
    {
        "vhx_version": "1.0",
        "id": "path-traversal-lfi",
        "title": "路径穿越读文件（LFI）",
        "category": "path-traversal",
        "cwe": "CWE-22",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "param_present", "location": "query",
             "name_hint": "file|path|filename|download|doc|template|page|img|src"}
        ],
        "surface": {"methods": ["GET"], "auth": "any"},
        "probe": {"action": "mutate_param", "sequence": ["http_request", "diff_response"]},
        "oracle": {"name": "file_signature_match",
                   "args": {"min_confidence": 0.85}},
        "evidence_required": [
            "request_canonical:probe", "response_sha256:probe", "status:probe",
            "content_type:probe",
        ],
        "counter_evidence": [
            "404/错误页把输入路径原样回显", "返回 HTML 壳（SPA 回退）",
            "返回 JSON 错误对象", "Content-Type 是 text/html 且无系统文件特征"
        ],
        "fp_traps": ["WAF 统一返回 200 空页", "路径被规范化后读到站内同名文件",
                     "框架自动加了 base 目录前缀"],
        "stop_conditions": ["连续 3 次 404", "连续 2 次被 WAF 拦截", "预算耗尽"],
        "budget": {"min_requests": 3, "max_requests": 10},
        "mutator_hints": [
            {"payload_class": "traversal_path", "note": "先打 /etc/passwd 这类高特征文件"},
            {"payload_class": "traversal_path_win", "note": "Linux 无特征时试 Windows"},
        ],
        "report_note": "必须附命中的系统文件正特征（如 passwd 行）并说明未读到文件时的负证据。",
    },
    {
        "vhx_version": "1.0",
        "id": "open-redirect",
        "title": "开放重定向",
        "category": "open-redirect",
        "cwe": "CWE-601",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "param_present", "location": "query",
             "name_hint": "url|redirect|next|return|returnUrl|callback|continue|target"}
        ],
        "surface": {"methods": ["GET"], "auth": "any"},
        "probe": {"action": "mutate_param", "sequence": ["http_request", "diff_response"]},
        "oracle": {"name": "redirect_target_match",
                   "args": {"expected_host": "redirect.test", "allow_suffix": True}},
        "evidence_required": [
            "request_canonical:probe", "response_sha256:probe", "status:probe",
        ],
        "counter_evidence": [
            "Location 是相对路径", "跳转回同站", "返回 200 而非 3xx",
            "站内白名单把外部地址改写成首页"
        ],
        "fp_traps": ["跳转页先 200 再 JS 跳（不是服务端重定向）",
                     "Location 被 URL 编码但仍同站"],
        "stop_conditions": ["连续 3 次 200", "连续 2 次被 WAF 拦截", "预算耗尽"],
        "budget": {"min_requests": 2, "max_requests": 8},
        "mutator_hints": [{"payload_class": "external_url",
                           "note": "只观察 Location，不跟跳（follow_redirects 关）"}],
        "report_note": "必须给出完整 Location 与 302 状态；仅前端 JS 跳转不算。",
    },
    {
        "vhx_version": "1.0",
        "id": "jwt-trust-boundary",
        "title": "JWT 信任边界（签名未被校验）",
        "category": "authentication",
        "cwe": "CWE-347",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "identity_available", "role": "probe"},
            {"kind": "param_present", "location": "header", "name_hint": "authorization"},
        ],
        "surface": {"methods": ["GET"], "auth": "required"},
        "probe": {"action": "swap_identity",
                  "sequence": ["http_request", "swap_identity", "diff_response"]},
        "oracle": {"name": "jwt_acceptance_check",
                   "args": {"min_similarity_ok": 0.90, "max_similarity_deny": 0.50}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "identity:baseline", "status:probe",
        ],
        "counter_evidence": [
            "伪造 token 返回 401/403", "返回 200 但是登录页/错误页",
            "响应与合法身份差异大（similarity<=0.5）", "服务端回落到匿名身份"
        ],
        "fp_traps": ["网关先按 cookie 认证、Authorization 只是摆设",
                     "token 里没有 exp，服务端另查会话表",
                     "响应被缓存导致两身份内容相同"],
        "stop_conditions": ["连续 2 次 401/403", "连续 2 次被 WAF 拦截", "预算耗尽"],
        "budget": {"min_requests": 2, "max_requests": 8},
        "mutator_hints": [
            {"payload_class": "jwt_forged", "payload_variant": "none",
             "note": "alg=none + 空签名，经典实现缺陷"},
            {"payload_class": "jwt_forged", "payload_variant": "strip",
             "note": "保留 alg 但清空签名，检验是否真的验签"},
        ],
        "report_note": "必须同时给出合法 token 与伪造 token 两条证据；只报 200 不算，要看内容是否等价。",
    },
    {
        "vhx_version": "1.0",
        "id": "xss-reflected",
        "title": "反射型 XSS（脚本实际执行）",
        "category": "injection",
        "cwe": "CWE-79",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "param_present", "location": "query", "name_hint": "q"},
        ],
        "surface": {"methods": ["GET"], "auth": "anonymous"},
        "probe": {"action": "browser_nav", "sequence": ["browser_nav"]},
        "oracle": {"name": "dom_marker_present", "args": {"min_confidence": 0.85}},
        "evidence_required": [
            "request_canonical:probe", "response_sha256:probe",
            "dom_snapshot:probe", "nonce:probe", "execution_marker:window_name",
        ],
        "counter_evidence": [
            "DOM 里有载荷文本但没有 data-pta-xss 属性（只反射未执行）",
            "window.name 未被写入", "CSP 拦截内联事件处理器",
            "输入被 HTML 实体编码后输出",
        ],
        "fp_traps": ["服务端把 < > 编码，但页面别处有反射点",
                     "响应头 X-XSS-Protection 让浏览器静默过滤",
                     "同一路径 GET 与 POST 的编码规则不同"],
        "stop_conditions": ["连续 2 次无执行痕迹", "预算耗尽"],
        "budget": {"min_requests": 1, "max_requests": 4},
        "mutator_hints": [
            {"payload_class": "xss_marker", "param_path": "query:q",
             "note": "脚本写 window.name 并给 body 打属性，用于区分执行与反射"},
        ],
        "report_note": "必须给出 DOM 快照证据与 nonce；只证明载荷出现在 HTML 里不足以定级。",
    },
    {
        "vhx_version": "1.0",
        "id": "mass-assignment-privilege",
        "title": "批量赋值提权（多塞权限字段被写库）",
        "category": "broken-access-control",
        "cwe": "CWE-915",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "param_present", "location": "body",
             "name_hint": "role|is_admin|admin|user_type|account_type|privilege"},
        ],
        "surface": {"methods": ["POST", "PUT", "PATCH"], "auth": "required"},
        "probe": {
            "action": "mutate_param",
            "sequence": ["http_request", "mutate_param", "diff_response"],
            "body_corpus": {
                "required": True,
                "hint": "先用合法字段提交一次拿到 200（body_json），否则 baseline 无法与 probe 比较",
            },
        },
        "oracle": {
            "name": "field_escalation_effect",
            "args": {"min_delta": 1, "require_privilege_delta": True},
        },
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "identity:probe", "status:probe",
        ],
        "counter_evidence": [
            "probe 返回 400/422（未知字段被校验拒绝）",
            "响应里的权限字段与 baseline 同级（字段被忽略）",
            "probe 返回 401/403（写接口另有授权校验）",
            "响应体不是 JSON，无法量化权限等级",
        ],
        "fp_traps": [
            "字段被接受但只写进本地展示层，未真正授权",
            "返回体回显了请求字段（回显≠生效）",
            "PUT 全量覆盖把其他字段清空，看起来差异大但没提权",
        ],
        "stop_conditions": ["连续 2 次 400/422", "连续 2 次 401/403", "预算耗尽"],
        "budget": {"min_requests": 2, "max_requests": 8},
        "mutator_hints": [
            {"payload_class": "extra_field", "param_path": "body:*",
             "note": "整体塞 role=admin + is_admin=true；有点路径时用 body:user.role"},
        ],
        "report_note": "必须给出 baseline 与 probe 两条证据，并注明响应里被抬高的权限字段路径与等级变化。",
    },
    {
        "vhx_version": "1.0",
        "id": "sqli-time-blind",
        "title": "时间盲注（无回显，靠延时分布判定）",
        "category": "injection",
        "cwe": "CWE-89",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "param_present", "location": "query", "name_hint": "id|q|search|sort"},
        ],
        "surface": {"methods": ["GET"], "auth": "any"},
        "probe": {
            "action": "timing_sample",
            "sequence": ["http_request", "mutate_param", "timing_sample", "diff_response"],
            # 时间判定必须有对照：没有 baseline 就分不清"慢了"是注入还是目标自己抖
            "baseline": {"required": True},
        },
        "oracle": {
            "name": "timing_distribution_shift",
            "args": {"min_samples": 5, "cv_max": 0.15, "min_effect_ms": 1800,
                     "alpha": 0.01, "n_boot": 10000},
        },
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "timing_sample:baseline", "timing_sample:probe",
            "identity:probe", "status:probe",
        ],
        "counter_evidence": [
            "基线组自身抖动很大（CV 超阈值），差距不可归因",
            "注入组只慢了一次，后续采样回落到基线",
            "probe 返回 4xx/5xx，没有可比较的正常响应",
            "存在缓存/CDN，重复请求命中缓存导致耗时不可比",
        ],
        "fp_traps": [
            "首次请求有冷启动/连接建立开销，被误判成注入延时",
            "服务端按参数长度限流，载荷变长导致变慢",
            "SLEEP 被 WAF 拦下返回 403 页面（看着像成功，状态码不对）",
        ],
        "stop_conditions": ["连续 2 次采样不足", "CV 超阈值 2 轮", "预算耗尽"],
        "budget": {"min_requests": 12, "max_requests": 24},
        "mutator_hints": [
            {"payload_class": "delay_short", "param_path": "query:id",
             "note": "SLEEP(2) 秒；基线用同一请求不带载荷，两组各采样 6 次（首次是冷启动，统计前丢弃）"},
        ],
        "report_note": "必须给出两组采样耗时（至少各 5 次）、中位数、CV、p 值；只写「响应变慢」不算证据。",
    },
    {
        "vhx_version": "1.0",
        "id": "sqli-boolean-blind",
        "title": "布尔盲注（1=1 与 1=2 的响应被掰开）",
        "category": "injection",
        "cwe": "CWE-89",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "param_present", "location": "query", "name_hint": "id|q|search|sort|name"},
        ],
        "surface": {"methods": ["GET"], "auth": "any"},
        "probe": {
            "action": "mutate_param",
            # 三次请求：基线、真条件、假条件。role_hints 让 executor 把两份注入
            # 分别标成 probe_true / probe_false，oracle 才能判三角关系。
            "sequence": ["http_request", "mutate_param", "http_request", "diff_response"],
            "role_hints": [
                {"role": "probe_true", "payload_class": "boolean_true", "param_path": "query:id"},
                {"role": "probe_false", "payload_class": "boolean_false", "param_path": "query:id"},
            ],
        },
        "oracle": {
            "name": "boolean_response_split",
            "args": {"min_similarity_same": 0.90, "max_similarity_diff": 0.55},
        },
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe_true",
            "request_canonical:probe_false", "response_sha256:baseline",
            "response_sha256:probe_true", "response_sha256:probe_false",
            "status:probe_true", "status:probe_false",
        ],
        "counter_evidence": [
            "两份注入响应完全一致（参数没进查询）",
            "真条件就把页面打坏（500/白屏），差异不来自布尔条件",
            "差异方向相反：假条件更像基线",
            "响应属于统一错误页或登录跳转",
        ],
        "fp_traps": [
            "页面本身有随机内容（广告位/时间戳），两份响应天然不同",
            "服务端对超长参数限流，1=2 更短反而更慢/更快",
            "WAF 只拦带单引号的请求，两个条件都返回 403",
        ],
        "stop_conditions": ["连续 3 次 403/429", "熔断打开", "预算耗尽"],
        "budget": {"min_requests": 3, "max_requests": 10},
        "report_note": "必须给出 baseline / probe_true / probe_false 三条证据与两个相似度；"
                       "只写「返回内容不同」不算证据，要说明差异确实由布尔条件引起。",
    },
   {
        "vhx_version": "1.0",
        "id": "idor-write-object",
        "title": "对象写入越权（改别人的对象，属主回读能看到）",
        "category": "broken-access-control",
        "cwe": "CWE-639",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "identity_available", "role": "probe"},
            {"kind": "param_present", "location": "body", "name_hint": "name|title|description|nickname"},
        ],
        "surface": {"methods": ["PUT", "PATCH", "POST"], "auth": "required"},
        "probe": {
            "action": "mutate_param",
            # baseline 是属主读到原样；probe 是攻击者写；verify 是属主再读一次。
            # 只有"写被接受 + 属主回读到标记"同时成立，才叫写入越权。
            "sequence": ["http_request", "swap_identity", "mutate_param", "http_request"],
            "baseline": {"method": "GET"},
            "verify_after": {"role": "verify", "identity": "baseline", "method": "GET"},
            "body_corpus": {
                "required": False,
                "hint": "目标要合法字段才收写入时，用 --body-json 给一份（标记会加到 name 上）",
            },
        },
        "oracle": {"name": "write_effect_visible", "args": {"max_changed": 4}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "request_canonical:verify", "response_sha256:baseline",
            "response_sha256:probe", "response_sha256:verify",
            "identity:probe", "identity:verify", "status:probe", "status:verify",
        ],
        "counter_evidence": [
            "probe 返回 401/403（写接口另有对象级授权）",
            "probe 返回 400/422（字段被校验拒绝）",
            "属主回读与基线完全一致（写入没有落到该对象）",
            "回读变了但没有本次标记（变化不可归因）",
        ],
        "fp_traps": [
            "服务端返回 200 但把写入排进队列，实际没生效",
            "写入在响应里回显了标记，但读接口从别的存储读（回显≠生效）",
            "PATCH 全量覆盖清空其它字段，看起来差异大但没改到属主对象",
            "回读页面有随机内容（计数/时间戳），变化多到无法归因",
        ],
        "stop_conditions": ["连续 2 次 401/403", "连续 2 次 400/422", "熔断打开", "预算耗尽"],
        "budget": {"min_requests": 3, "max_requests": 8},
        "mutator_hints": [
            {"payload_class": "write_marker", "param_path": "body:*",
             "note": "标记写到 name 上；目标要合法字段时用 --body-json 给一份"},
        ],
        "report_note": "必须给出 baseline / probe / verify 三条证据，并写明「写入身份 ≠ 属主身份」"
                       "与回读里出现的标记字段路径；只给 200 不算证据。",
    },
    {
        "vhx_version": "1.0",
        "id": "upload-rce",
        "title": "未授权文件上传（回读命中本次标记）",
        "category": "file-upload",
        "cwe": "CWE-434",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "param_present", "location": "body",
             "name_hint": "file|upload|attachment|avatar|image"},
        ],
        "surface": {"methods": ["POST", "PUT"], "auth": "any"},
        "probe": {
            "action": "mutate_param",
            # 三段：上传（probe）→ 回读（verify）。回读地址由"文件落到哪"决定，
            # 模板只能给最常见约定，操作者用 Target.verify_url 覆盖成真实路径。
            "sequence": ["http_request", "mutate_param", "http_request", "diff_response"],
            "baseline": {"method": "GET"},
            "verify_after": {"role": "verify", "identity": "probe", "method": "GET",
                             "url_suffix": "/uploads/pta_upload.html"},
        },
        "oracle": {
            "name": "upload_readback",
            "args": {"success_status": [200, 201, 204],
                     "executable_types": ["text/html", "php", "javascript", "text/x-"]},
        },
        "evidence_required": [
            "request_canonical:probe", "request_canonical:verify",
            "response_sha256:probe", "response_sha256:verify",
            "status:probe", "status:verify",
        ],
        "counter_evidence": [
            "上传返回 400/415（类型或字段被校验拒绝）",
            "上传返回 401/403（接口另有授权）",
            "回读 404（文件被改名或落到不可预测的路径）",
            "回读 200 但正文里没有本次标记（取回的是别的文件/目录页）",
        ],
        "fp_traps": [
            "上传响应回显了文件内容，但文件没有真的落盘（回显≠落地）",
            "回读命中的是上一次遗留的同名文件",
            "服务端把上传目录挂成静态资源，返回 200 但 Content-Type 被强制 octet-stream",
            "CDN 缓存了旧内容，回读到的是历史文件",
        ],
        "stop_conditions": ["连续 2 次 400/415", "连续 2 次 401/403", "熔断打开", "预算耗尽"],
        "budget": {"min_requests": 3, "max_requests": 8},
        "mutator_hints": [
            {"payload_class": "upload_shell", "param_path": "body:file",
             "note": "文件名固定 pta_upload.html，标记写在文件内容里；回读路径见 verify_after"},
        ],
        "report_note": "必须写清「回读返回的 Content-Type」与「是否可执行」：可被当 html/php 返回"
                       "才叫上传 RCE，只能下载原文只能算未授权文件落地。",
    },
    {
        "vhx_version": "1.0",
        "id": "xxe-entity",
        "title": "XML 外部实体注入（带外确认）",
        "category": "injection",
        "cwe": "CWE-611",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
        ],
        "surface": {"methods": ["POST", "PUT"], "auth": "any"},
        "probe": {"action": "oob_arm",
                  "sequence": ["oob_arm", "mutate_param", "oob_check"]},
        "oracle": {"name": "oob_callback_received",
                   "args": {"min_callbacks": 1, "require_http": False}},
        "evidence_required": [
            "request_canonical:probe", "response_sha256:probe", "oob_token",
            "callback:source_ip", "callback:path",
        ],
        "counter_evidence": [
            "目标返回 400/415（不收 XML）",
            "实体被剥离（DOCTYPE 被删）且无回连",
            "回连来源是我方出口 IP（自触发，不是目标解析）",
            "只在响应里回显了实体名，没有真的去取（回显≠解析）",
        ],
        "fp_traps": [
            "解析器只做 DTD 语法检查，不解析外部实体",
            "安全设备主动回连探测，看着像目标的请求",
            "XML 被当成普通字符串存库，压根没进解析器",
        ],
        "stop_conditions": ["连续 2 次 400/415", "回连全为自触发", "预算耗尽"],
        "budget": {"min_requests": 2, "max_requests": 8},
        "mutator_hints": [
            {"payload_class": "xxe_entity", "param_path": "body:xml",
             "note": "整段 XML 替换请求体；实体引用 {oob}，解析器去取它就回连"},
        ],
        "report_note": "必须给出回连时间、源 IP 与路径；只有 DNS 证据时降级为 hypothesis。",
    },
    {
        "vhx_version": "1.0",
        "id": "deserialization-marker",
        "title": "反序列化入口存在（解析到类名后报错）",
        "category": "insecure-deserialization",
        "cwe": "CWE-502",
        "side_effect_level": "L1",
        "requires_approval": False,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
        ],
        "surface": {"methods": ["POST", "PUT"], "auth": "any"},
        "probe": {"action": "mutate_param",
                  "sequence": ["http_request", "mutate_param", "diff_response"],
                  "baseline": {"required": True}},
        "oracle": {"name": "deserialization_marker_present", "args": {}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "status:probe",
        ],
        "counter_evidence": [
            "目标返回 400/415（不收序列化流）",
            "响应里没有反序列化异常（载荷被当普通字节丢掉）",
            "基线也报同样异常（错误来自框架默认处理，不可归因）",
            "异常栈里没有我们的类名（可能只是碰巧匹配了通用词）",
        ],
        "fp_traps": [
            "统一错误页里本来就带 InvalidClassException 之类的词",
            "服务端先做类型校验再解析，报错来自校验而不是反序列化",
            "WAF 自带的 Java 安全提示文案",
        ],
        "stop_conditions": ["连续 3 次 400/415", "熔断打开", "预算耗尽"],
        "budget": {"min_requests": 2, "max_requests": 8},
        "mutator_hints": [
            {"payload_class": "deser_java", "param_path": "body:data",
             "note": "Java 序列化魔术字节 + 不存在的类名，命中即证明进了 ObjectInputStream"},
        ],
        "report_note": "只能写「反序列化入口存在」，不能写「反序列化 RCE」："
                       "报错证明载荷被解析，不证明存在可用 gadget。",
    },
    {
        "vhx_version": "1.0",
        "id": "race-condition-idempotency",
        "title": "并发重复提交（同一操作被接受多次）",
        "category": "race-condition",
        "cwe": "CWE-362",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "endpoint_exists", "path": "/"},
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "param_present", "location": "body", "name_hint": "id|code|coupon|token|order"},
        ],
        "surface": {"methods": ["POST", "PUT", "PATCH"], "auth": "any"},
        "probe": {
            "action": "concurrent_burst",
            # burst 是"同时发几发"。5 是经验值：再多只是把同一结论重复得更贵，
            # 再少则可能被 TCP 握手差异摊成顺序执行。
            "burst": 5,
            "sequence": ["http_request", "concurrent_burst", "diff_response"],
            "baseline": {"required": True},
        },
        "oracle": {
            "name": "idempotency_violation",
            "args": {"burst": 5, "min_success": 2,
                     "success_status": [200, 201, 202, 204]},
        },
        "evidence_required": [
            "request_canonical:probe", "response_sha256:probe", "status:probe",
            "request_canonical:baseline", "response_sha256:baseline",
        ],
        "counter_evidence": [
            "只有 1 发拿到 2xx（其余 409/423/400：幂等性生效）",
            "全部被拒（400/401/403）：请求本身无效，不构成竞态证据",
            "5 发状态一致且都不是 2xx（参数没被接受）",
            "服务端把 N 发合并成一条（响应体带同一个 id，但确属幂等）",
        ],
        "fp_traps": [
            "接口本身就允许重复（发消息、记日志），重复接受是设计而不是缺陷",
            "前两发成功、后三发被限流挡住（429 不是幂等证据）",
            "响应 202 Accepted 只说明进队列，不代表执行了两次",
            "预发/演示环境，本身没接支付或库存",
        ],
        "stop_conditions": ["连续 2 次 401/403", "熔断打开", "预算耗尽"],
        "budget": {"min_requests": 6, "max_requests": 14},
        "mutator_hints": [
            {"payload_class": "write_marker", "param_path": "body:*",
             "note": "N 发用同一个标记（nonce 固定），否则测的是 N 个不同操作"},
        ],
        "report_note": "必须写明并发的发数、每发的状态码，以及「重复被接受」与"
                       "「业务上确实扣了两次」是两件事：后者要读余额/流水，本模板不读。",
    },
    {
        "vhx_version": "1.0",
        "id": "csrf-token-not-enforced",
        "title": "CSRF 令牌未被强制校验",
        "category": "csrf",
        "cwe": "CWE-352",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "identity_available", "role": "probe"},
            {"kind": "param_present", "location": "header|body", "name_hint": "csrf"},
        ],
        "surface": {"methods": ["POST", "PUT", "PATCH", "DELETE"], "auth": "required"},
        "probe": {
            "action": "http_request",
            # 三发：带令牌一次、摘掉令牌一次、比一次。少的不是请求，是那个头。
            "sequence": ["http_request", "http_request", "diff_response"],
            "baseline": {"required": True,
                         "hint": "带令牌的同一请求先跑一次：它不成功，这次测试就不成立"},
            "strip": {
                "apply": "probe",
                # 只摘令牌类，不碰 authorization/cookie：
                # 把身份也摘了就从 CSRF 变成匿名访问测试，两者结论不同。
                "headers": ["x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrf",
                            "x-csrftoken"],
                "params": ["_csrf", "csrf_token", "authenticity_token", "csrf"],
            },
            # 匿名对照：同一个接口不带会话再打一次。
            # 它不是"对照组"，是"分辨器"——匿名也能成功说明缺的是授权不是令牌，
            # 那这条结论就该从 CSRF 改判成越权（oracle 会降到 0.20）。
            "control": {"identity": "none"},
        },
        "oracle": {"name": "csrf_token_not_enforced", "args": {}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "identity:probe", "status:baseline", "status:probe",
        ],
        "counter_evidence": [
            "摘掉令牌后被拒（401/403）",
            "带令牌的原始请求本身就没成功（测试不成立，不是漏报也不是洞）",
            "摘掉令牌后状态码变了但不是成功（302 跳登录、400 参数错）",
            "响应体写着「令牌无效 / 校验失败」但状态码是 200",
            "匿名请求同 URL 也能成功：这是缺失授权，不是 CSRF",
        ],
        "fp_traps": [
            "接口幂等且无副作用（删一个已删的也回 204），2xx 不代表操作生效",
            "框架把令牌从 Cookie 读（双提交），此时摘 header 本就不影响",
            "请求被前置网关改写成 GET：GET 一般不校验令牌",
            "会话本身已过期，服务端回 200 + 统一壳页",
        ],
        "stop_conditions": ["连续 2 次 401/403", "摘令牌后 302 到登录页", "预算耗尽"],
        "budget": {"min_requests": 2, "max_requests": 8},
        "mutator_hints": [],
        "report_note": "要写清三发的状态码，并注明有没有做匿名对照：没有对照只能说明"
                       "「令牌不是放行条件」，不能排除接口本来就不需要身份。",
    },
    {
        "vhx_version": "1.0",
        "id": "xss-stored-marker",
        "title": "存储型 XSS（写入的标记被原样渲染）",
        "category": "xss",
        "cwe": "CWE-79",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "identity_available", "role": "baseline"},
            {"kind": "param_present", "location": "body",
             "name_hint": "content|comment|body|message|description|name|title"},
        ],
        "surface": {"methods": ["POST", "PUT", "PATCH"], "auth": "required"},
        "probe": {
            "action": "mutate_param",
            "sequence": ["http_request", "mutate_param", "http_request", "diff_response"],
            "verify_after": {
                "identity": "baseline",
                "method": "GET",
                # 不给 url：回落到 target.url 的 GET（写集合、读列表是同一路径）。
                # 读回点在别处时用 `pta run --verify-url` 指定，模板不猜。
                "label": "readback",
            },
        },
        "oracle": {"name": "stored_marker_reflected", "args": {"attr_name": "data-pta"}},
        "evidence_required": [
            "request_canonical:probe", "request_canonical:verify",
            "response_sha256:probe", "response_sha256:verify",
            "status:probe", "status:verify", "content_type:verify",
        ],
        "counter_evidence": [
            "回读里没有本次写入的标记（只回显、没落库）",
            "标记出现但被 HTML 转义（&lt; / &#…）",
            "标记以 JSON 返回：浏览器不会把它当 HTML 解析",
            "写入被拒（401/403）或参数校验失败（400/422）",
        ],
        "fp_traps": [
            "写入接口把内容回显在自己的响应里，看起来像「已存储」",
            "页面用 innerHTML 渲染但做了 sanitize（回读看不出，需要浏览器确认）",
            "回读命中的是别人早先写下的同名标记（nonce 保证不会）",
            "回读来自 CDN 缓存，实际数据并未落库",
        ],
        "stop_conditions": ["连续 2 次 401/403", "回读与写入是同一发请求", "预算耗尽"],
        "budget": {"min_requests": 3, "max_requests": 8},
        "mutator_hints": [
            {"payload_class": "stored_xss_marker", "param_path": "body:content",
             "note": "字段名由目标决定，用 --param body:<字段> 覆盖"},
        ],
        "report_note": "必须同时给出写入与回读两条证据；回读类型不是 HTML 时要写明"
                       "「原样存储 ≠ 会执行」，不能直接报 XSS。",
    },
    {
        "vhx_version": "1.0",
        "id": "logic-negative-amount",
        "title": "业务逻辑：负数金额被接受",
        "category": "business-logic",
        "cwe": "CWE-840",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "identity_available", "role": "probe"},
            {"kind": "param_present", "location": "body", "name_hint": "amount"},
        ],
        "surface": {"methods": ["POST", "PUT", "PATCH"], "auth": "required"},
        "probe": {"action": "mutate_param",
                  "sequence": ["http_request", "mutate_param", "http_request", "diff_response"],
                  "verify_after": {"identity": "baseline", "method": "GET", "label": "readback"}},
        "oracle": {"name": "numeric_boundary_accepted", "args": {"expect_value": "-100"}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "request_canonical:readback", "response_sha256:readback",
            "identity:probe", "status:probe",
        ],
        "counter_evidence": [
            "probe 返回 400/422——范围校验在起作用",
            "回读里没有 -100——值被夹紧、或写入没生效",
            "回读拿不到（401/404）——看不到存下来的值",
            "请求体里的金额是字符串：服务端没把它当数值处理",
        ],
        "fp_traps": [
            "这个接口本来就把负数当冲正/退款语义（业务允许）",
            "回读页是静态模板，不含实际数值",
            "写接口只回 204，回读点在另一个资源（要 --verify-url）",
            "金额单位是分/万元，-100 在业务上其实是 -1 元",
        ],
        "stop_conditions": ["连续 3 次 400", "预算耗尽"],
        "budget": {"min_requests": 3, "max_requests": 10},
        "mutator_hints": [
            {"payload_class": "negative_number", "param_path": "body:amount",
             "note": "字段名由目标决定，用 --param body:<字段> 覆盖"},
        ],
        "report_note": "必须给出「写入请求 + 回读」两条证据，并写清回读里出现的是哪个字段；"
                       "只写「接口返回 200」不算。业务后果（能不能换钱）要单独说明。",
    },
    {
        "vhx_version": "1.0",
        "id": "logic-quantity-overflow",
        "title": "业务逻辑：超出范围的数量被接受",
        "category": "business-logic",
        "cwe": "CWE-1284",
        "side_effect_level": "L2",
        "requires_approval": True,
        "preconditions": [
            {"kind": "identity_available", "role": "probe"},
            {"kind": "param_present", "location": "body", "name_hint": "quantity"},
        ],
        "surface": {"methods": ["POST", "PUT", "PATCH"], "auth": "required"},
        "probe": {"action": "mutate_param",
                  "sequence": ["http_request", "mutate_param", "http_request", "diff_response"],
                  "verify_after": {"identity": "baseline", "method": "GET", "label": "readback"}},
        "oracle": {"name": "numeric_boundary_accepted", "args": {"expect_value": "999999999"}},
        "evidence_required": [
            "request_canonical:baseline", "request_canonical:probe",
            "response_sha256:baseline", "response_sha256:probe",
            "request_canonical:readback", "response_sha256:readback",
            "identity:probe", "status:probe",
        ],
        "counter_evidence": [
            "probe 返回 400/422——范围校验在起作用",
            "回读里没有 999999999——值被夹到库存上限",
            "回读拿不到（401/404）——看不到存下来的值",
            "服务端把数量当字符串存，实际计算时仍走校验",
        ],
        "fp_traps": [
            "接口允许超卖（业务上就叫预售），不是缺陷",
            "数量字段是分页/排序参数，与库存无关",
            "回读返回的是商品定义而不是库存快照",
        ],
        "stop_conditions": ["连续 3 次 400", "预算耗尽"],
        "budget": {"min_requests": 3, "max_requests": 10},
        "mutator_hints": [
            {"payload_class": "huge_number", "param_path": "body:quantity",
             "note": "字段名由目标决定，用 --param body:<字段> 覆盖"},
        ],
        "report_note": "必须给出回读里那个数量落在哪个字段；只说「接口接受了」不算，"
                       "要说明它是否影响了库存/总额这类可计算的量。",
    },
]
