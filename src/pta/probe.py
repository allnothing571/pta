"""http_probe：整个系统里唯一碰 socket 的工具。

对外只返回 Extract（脱敏视图）；原始字节进 CAS。
执行序列固定 11 步，任何一步失败都写 action_log 并返回结构化状态。
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit

from . import payloads
from . import jwtlab
from .approvals import ApprovalGate
from .budget import Budget
from .cas import Cas
from .errors import (ApprovalRequired, BudgetExceeded, DnsPinViolation, PayloadRejected,
                     ScopeViolation)
from .models import (Body, CanonicalRequest, Evidence, Extract, Header, RawResponse,
                     ResolvedRequest, preview_text, sha256_hex)
from .scope import DnsPin, Scope, check_request
from .store import Store
from .transport import Transport, TransportError
from .vault import Vault

MAX_BODY = 4 * 1024 * 1024
_KEEP_RESP_HEADERS = ("content-type", "content-length", "location", "server",
                      "x-powered-by", "www-authenticate", "set-cookie-len",
                      # 拦截层常留的头：正文可能被定制成普通 403 页，头还在。
                      # 只保留名字与值，不保留任何 cookie 内容。
                      "cf-ray", "cf-cache-status", "cf-mitigated",
                      "x-sucuri-id", "x-sucuri-block", "x-iinfo",
                      "x-amzn-requestid", "x-amzn-waf-action", "x-amz-cf-id",
                      "akamai-grn", "x-mod-security", "x-protected-by")


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def compute_evidence_id(request_json: Dict[str, Any], body_sha256: str, label: str) -> str:
    """时间不参与。同一请求采样 5 次得到同一个 id。"""
    payload = json.dumps(
        {"req": request_json, "body": body_sha256, "label": label},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class ProbeRequest:
    action_id: str
    url: str
    method: str = "GET"
    identity: str = "none"
    label: str = "single"
    param_path: Optional[str] = None
    payload_class: Optional[str] = None
    payload_variant: Optional[str] = None
    sample: int = 1
    follow_redirects: bool = False
    max_hops: int = 3
    timeout_s: float = 10.0
    headers_extra: Tuple[Tuple[str, str], ...] = ()
    body_kind: str = "none"
    body_json: Optional[Dict[str, Any]] = None
    level: Optional[str] = None
    asset_node_id: Optional[str] = None
    id_plus_one: Optional[str] = None
    oob_token: Optional[str] = None
    # 固定 nonce：竞态判定要 N 发**一模一样**的请求，随机 nonce 会让它们变成
    # "N 个不同操作"，服务端把它们当不同订单处理就测不出重复提交。
    nonce_value: Optional[str] = None
    # CSRF 判定要"把令牌从请求里摘掉，其余一字不改"：这两项按名字删头/删参数。
    # 只删名字匹配的东西，不重排、不改值——否则「去令牌后仍 2xx」可能是被改坏的
    # 请求撞上了另一个分支，而不是"令牌不是放行条件"。
    strip_headers: Tuple[str, ...] = ()
    strip_params: Tuple[str, ...] = ()


@dataclass
class ProbeResult:
    status: str  # ok | denied | blocked | error | not_modified | pending_approval
    reason: str = ""
    evidence_id: Optional[str] = None
    extract: Optional[Extract] = None
    approval_fp: Optional[str] = None
    # 真跟过去的每一跳（绝对地址），按顺序。诊断「落地在哪」用。
    redirects: Tuple[str, ...] = ()
    # 没跟成的那一跳：`目标地址|原因`。跳到没授权的端口、或那一跳连不上时就是它。
    redirect_blocked: str = ""

    def to_json(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "evidence_id": self.evidence_id,
            "approval_fp": self.approval_fp,
            "extract": self.extract.to_json() if self.extract else None,
            "redirects": list(self.redirects),
            "redirect_blocked": self.redirect_blocked,
        }


class ProbeTool:
    def __init__(self, scope: Scope, store: Store, cas: Cas, transport: Transport,
                 gate: ApprovalGate, budget: Budget, vault: Vault,
                 dns: Optional[DnsPin] = None, oob_host: Optional[str] = None, bus=None,
                 oob=None):
        self.scope = scope
        self.store = store
        self.cas = cas
        self.transport = transport
        self.gate = gate
        self.budget = budget
        self.vault = vault
        self.dns = dns or DnsPin()
        self.oob_host = oob_host or (oob.public_host if oob is not None else None)
        self.oob = oob
        self.bus = bus

    # ---------- 主流程 ----------
    def run(self, req: ProbeRequest) -> ProbeResult:
        return self._guarded(req)

    def _guarded(self, req: ProbeRequest, skip_budget: bool = False,
                 gate: Optional[threading.Barrier] = None) -> ProbeResult:
        try:
            return self._run(req, skip_budget=skip_budget, gate=gate)
        except DnsPinViolation as exc:
            self._log(req, "denied", str(exc), level=req.level or "L1")
            return ProbeResult("denied", "dns_pin: %s" % exc)
        except ScopeViolation as exc:
            self._log(req, "denied", str(exc), level=req.level or "L1")
            return ProbeResult("denied", str(exc))
        except BudgetExceeded as exc:
            self._log(req, "blocked", str(exc), level=req.level or "L1")
            return ProbeResult("blocked", str(exc))
        except PayloadRejected as exc:
            self._log(req, "denied", str(exc), level=req.level or "L1")
            return ProbeResult("denied", "payload: %s" % exc)
        except TransportError as exc:
            self._log(req, "error", str(exc), level=req.level or "L1")
            return ProbeResult("error", str(exc))
        except KeyError as exc:
            self._log(req, "error", "vault: %s" % exc, level=req.level or "L1")
            return ProbeResult("error", "vault: %s" % exc)

    def _run(self, req: ProbeRequest, skip_budget: bool = False,
             gate: Optional[threading.Barrier] = None) -> ProbeResult:
        # 1-3. 目标解析 + 范围 + 方法/等级
        level = req.level or (payloads.level_floor(req.payload_class) if req.payload_class else "L1")
        host, scheme, port, raw_path = check_request(self.scope, req.method, req.url, level)
        parsed = urlsplit(req.url)
        query: List[Tuple[str, str]] = list(parse_qsl(parsed.query, keep_blank_values=True))

        # 4. 审批门
        allowed, fp, why = self.gate.check(
            self.scope.engagement_id, "http_probe", host, req.param_path, req.payload_class, level
        )
        if not allowed:
            self._log(req, "pending_approval", why, host=host, level=level, fp=fp)
            if self.bus is not None:
                self.bus.publish({"type": "approval_required", "fp": fp, "host": host,
                                  "url": req.url, "level": level, "label": req.label})
            return ProbeResult("pending_approval", why, approval_fp=fp)

        # 5. DNS pin
        pinned = self.dns.pin(host, self.scope)

        # 6. 构造请求（含载荷）
        headers, body = self._build(req, host, port)
        if req.strip_params:
            # CSRF 令牌也可能放在表单/query 里（`?_csrf=…`）：同样只按名字摘掉。
            drop = {p.lower() for p in req.strip_params}
            query = [(k, v) for k, v in query if k.lower() not in drop]
        query = self._apply_payload_query(req, query)
        body = self._apply_payload_body(req, body)

        canonical = CanonicalRequest(
            engagement_id=self.scope.engagement_id,
            method=req.method.upper(),
            scheme=scheme,
            host=host,
            port=port,
            raw_path=raw_path,
            query=tuple(query),
            headers=headers,
            body=body,
            identity=req.identity,
            asset_node_id=req.asset_node_id,
            param_path=req.param_path,
            payload_class=req.payload_class,
            payload_variant=req.payload_variant,
            side_effect_level=level,
        )

        resolved = self._resolve(canonical, pinned)

        # 7. 预算（并发突发已经一次占好号，这里跳过，否则 N 发会被限速摊开）
        if not skip_budget:
            self.budget.take(host)

        # 8. 发送（sample 次）
        # 竞态要的是"同时出网"，不是"同时开始准备"：DNS 固定、请求体加密落盘、
        # 头拼装都在闸门之前做完，闸门一开就只剩 write 一句。
        if gate is not None:
            try:
                gate.wait(timeout=5.0)
            except threading.BrokenBarrierError:
                pass  # 有线程提前倒了：剩下的照发，别让整组卡死
        responses: List[RawResponse] = []
        for _ in range(max(1, req.sample)):
            responses.append(self.transport.send(resolved, timeout_s=req.timeout_s))
            # 只把"服务器要求我们慢下来/暂时不可用"算成被挡（429/503）。
            # 403 不能进熔断：应用层鉴权失败也是 403，一个防护良好的目标
            # 光撞几个受保护接口就能把熔断打开，之后整场演练全被 blocked 掉。
            # "是不是 WAF" 由通道消歧（channels.py）用响应特征回答。
            self.budget.breaker.record(responses[-1].status in (429, 503))
        first = responses[0]

        # 9. 重定向跟随（可选，且每一跳重新过 scope）
        # Location 相对地址是常态（`/login`、`../x`），必须按当前位置解析；
        # 顺带把 `#fragment` 去掉（片段不上线路），把 Location 自带的 query 留下
        # ——原来的写法把 query 丢成空元组，形如 `?continue=/home` 的跳转会走偏。
        hops = 0
        follow_url = req.url
        seen_hops: List[str] = []
        blocked = ""
        while req.follow_redirects and 300 <= first.status < 400 and hops < req.max_hops:
            loc = (first.header("location") or "").strip()
            if not loc:
                break
            target, _frag = urldefrag(urljoin(follow_url, loc))
            try:
                host2, scheme2, port2, path2 = check_request(self.scope, "GET", target, level)
            except ScopeViolation as exc:
                # 跳到范围外（最常见：站点自己跳到未授权的端口）。浏览器到这儿也会停，
                # 我们同样停，但把这一跳记下来——"为什么只抓到 302"要能说得出来。
                blocked = "%s|%s" % (target, exc)
                break
            pinned2 = self.dns.pin(host2, self.scope)
            canonical2 = CanonicalRequest(
                engagement_id=canonical.engagement_id, method="GET", scheme=scheme2, host=host2,
                port=port2, raw_path=path2,
                query=tuple(parse_qsl(urlsplit(target).query, keep_blank_values=True)),
                headers=canonical.headers,
                body=Body(), identity=canonical.identity, param_path=canonical.param_path,
                payload_class=canonical.payload_class, side_effect_level=level,
            )
            self.budget.take(host2)
            try:
                first = self.transport.send(self._resolve(canonical2, pinned2),
                                            timeout_s=req.timeout_s)
            except TransportError as exc:
                # 这一跳打不通（典型：站点拼绝对地址时丢了端口，指到 80 口去）。
                # 不是我们的错，也不能把已经拿到的 302 证据丢掉，所以停在这儿并记一笔。
                blocked = "%s|%s" % (target, exc)
                break
            seen_hops.append(target)
            follow_url = target
            hops += 1

        # 10. 证据落库（脱敏 + 加密 + 索引）
        body_sha = sha256_hex(first.body)
        req_json = canonical.to_json()
        req_blob = self.cas.put(json.dumps(req_json, sort_keys=True).encode("utf-8"), kind="request")
        body_blob = self.cas.put(first.body, kind="response")
        ev_id = compute_evidence_id(req_json, body_sha, req.label)

        timings = tuple(round(r.total_ms(), 3) for r in responses)
        ev = Evidence(
            evidence_id=ev_id,
            engagement_id=canonical.engagement_id,
            label=req.label,
            identity=canonical.identity,
            request=canonical,
            status=first.status,
            content_type=first.header("content-type"),
            body_sha256=body_blob,
            body_len=len(first.body),
            headers=tuple((k, v) for k, v in first.headers if k.lower() in _KEEP_RESP_HEADERS),
            sample_count=len(responses),
            timings_ms=timings,
            ts_first=_now(),
            ts_last=_now(),
            request_blob=req_blob,
        )
        self.store.upsert_evidence(ev)

        # 11. 返回脱敏视图
        extract = Extract(
            evidence_id=ev_id,
            label=req.label,
            identity=canonical.identity,
            method=canonical.method,
            url=canonical.url(),
            status=first.status,
            content_type=first.header("content-type"),
            body_len=len(first.body),
            body_sha256=body_blob,
            sample_count=len(responses),
            total_ms_last=timings[-1],
            preview=preview_text(first.body),
            headers={k: v for k, v in ev.headers},
        )
        # `why` 落进日志：批过的、按类放行的、L1 自动过的，事后要分得开
        self._log(req, "ok", why, host=host, url=canonical.url(), level=level, fp=fp,
                  detail={"evidence_id": ev_id, "samples": len(responses),
                          "status": first.status, "param_path": req.param_path,
                          "payload_class": req.payload_class,
                          "redirects": list(seen_hops), "redirect_blocked": blocked})
        if level >= "L2":
            self.gate.consume_once(fp)
        return ProbeResult("ok", "", evidence_id=ev_id, extract=extract, approval_fp=fp,
                           redirects=tuple(seen_hops), redirect_blocked=blocked)

    # ---------- 内部 ----------
    def _build(self, req: ProbeRequest, host: str, port: int) -> Tuple[Tuple[Header, ...], Body]:
        headers = [
            Header("Host", "derived", value=host),
            Header("Accept", "literal", value="*/*"),
            Header("User-Agent", "literal", value="pta-p0/0.1"),
        ]
        auth_ref = "cred/%s/authorization" % req.identity
        token = self.vault.get(auth_ref) if req.identity != "none" else None
        if token and req.payload_class == "jwt_forged":
            # 伪造结果写成 literal：重放要能复现同一个 token，不能只存一个 vault 引用
            forged = jwtlab.forge(token, req.payload_variant or "none")
            headers.append(Header("Authorization", "literal", value=forged))
            token = None
        if token:
            headers.append(Header("Authorization", "vault_ref", ref=auth_ref,
                                  value_sha256=sha256_hex(token.encode("utf-8"))))
        # 身份带着的其它头（Cookie / X-CSRF-Token / X-Api-Key …）由 `pta auth` 导入，
        # 落在 cred/<identity>/<header>。这里统一注入，headers_extra 仍然能覆盖它们。
        # Host / Content-Length 例外：前者是范围判定的锚点，后者由本次请求体决定，
        # 都不能让凭证仓改（导入时已经滤过一遍，这里是兜底）。
        if req.identity != "none":
            for ref, val in self.vault.items("cred/%s/" % req.identity).items():
                name = ref.rsplit("/", 1)[-1]
                if name.lower() in ("authorization", "host", "content-length",
                                    "connection", "transfer-encoding"):
                    continue
                headers.append(Header(name, "literal", value=val))
        # headers_extra 是"覆盖"而不是"追加"：同名头（大小写不敏感）就地替换。
        # 否则会同时出现两个 User-Agent，服务端取第一条 = 默认的 pta-p0/0.1，
        # 通道消歧（channels.py）就白做了。
        # Host 例外：它是范围判定的锚点，不允许被载荷/通道改掉。
        by_name = {h.name.lower(): i for i, h in enumerate(headers)}
        for k, v in req.headers_extra:
            key = k.lower()
            if key == "host":
                continue
            if key in by_name:
                headers[by_name[key]] = Header(k, "literal", value=v)
            else:
                by_name[key] = len(headers)
                headers.append(Header(k, "literal", value=v))

        if req.strip_headers:
            # 摘掉指定的头。三个不许删：
            # - host 是范围判定的锚点，删了就不再指向同一目标；
            # - authorization / cookie 是"我是谁"，删了就从 CSRF 测试变成匿名访问
            #   测试（那是 authz 模板的事，两者结论不能混）。
            gone = {n.lower() for n in req.strip_headers} - {"host", "authorization", "cookie"}
            if gone:
                headers = [h for h in headers if h.name.lower() not in gone]

        body = Body()
        # 载荷自带 Content-Type 时，请求体由载荷整体决定（multipart / XML / 序列化流）。
        # 这条分支必须排在 JSON 之前：否则 body_kind 会先把它包成一个 JSON 字符串，
        # 服务端看到的就不是一个真正的上传请求了。
        cls = payloads.REGISTRY.get(req.payload_class) if req.payload_class else None
        if cls is not None and cls.content_type:
            raw = self._payload_value(req).encode(cls.encoding)
            body = Body(kind="raw", sha256=sha256_hex(raw),
                        blob=self.cas.put(raw, kind="request_body"), length=len(raw))
            headers.append(Header("Content-Type", "literal", value=cls.content_type))
            return tuple(headers), body
        body_json = req.body_json
        # body:* 类载荷（批量赋值）可能没有现成的合法请求体：先用空对象起底，
        # 由 _apply_payload_body 注入字段。有 corpus 时请用 body_json 提供真实字段。
        if body_json is None and req.payload_class and (req.param_path or "").startswith("body:"):
            body_json = {}
        if req.body_kind == "json" or body_json is not None:
            raw = json.dumps(body_json if body_json is not None else {},
                             separators=(",", ":")).encode("utf-8")
            body = Body(kind="json", sha256=sha256_hex(raw), blob=self.cas.put(raw, kind="request_body"),
                        length=len(raw))
            headers.append(Header("Content-Type", "literal", value="application/json"))
        return tuple(headers), body

    def _payload_value(self, req: ProbeRequest) -> str:
        """OOB 类载荷必须绑定本次 arm 出来的 token，不可复用旧 URL。"""
        if req.payload_class == "oob_url" and req.oob_token:
            if self.oob is None:
                raise PayloadRejected("未配置 OOB 收集器，无法生成回连地址")
            return self.oob.url_for(req.oob_token)
        cls = payloads.REGISTRY.get(req.payload_class) if req.payload_class else None
        if (cls is not None and cls.content_type and req.oob_token
                and "{oob}" in cls.render):
            # XXE 这类"整体替换请求体"的带外载荷：URL 必须带本次的 token。
            # 用随机 nonce 拼路径同样能收到回连，但 oob.wait(token) 按 token 匹配，
            # 结果就是"请求真发出去了、我们却等不到"。
            if self.oob is None:
                raise PayloadRejected("载荷需要回连地址，但未配置 OOB 收集器")
            return payloads.render(req.payload_class, oob=self.oob.url_for(req.oob_token),
                                   id_plus_one=req.id_plus_one, nonce_value=req.nonce_value)
        return payloads.render(req.payload_class, oob=self.oob_host,
                               id_plus_one=req.id_plus_one, nonce_value=req.nonce_value)

    def send_burst(self, reqs: Sequence[ProbeRequest]) -> List["ProbeResult"]:
        """同一请求同时发 N 发，给竞态判定用。

        和 run() 只有两处差别，都很关键：
        1. 预算一次占 N 个号（reserve_n）：逐发 take() 会按 min_interval 把 N 发
           摊成 N×间隔，量到的是"顺序一致性"，不是竞态；
        2. 用一个 Barrier 让 N 个线程尽量同一时刻出网。没有这一步，线程启动的
           先后就足够让服务端串行处理完每一发，"并发"只是名义上的。
        """
        reqs = list(reqs)
        if not reqs:
            return []
        host = urlsplit(reqs[0].url).hostname or ""
        try:
            self.budget.reserve_n(len(reqs), host)
        except BudgetExceeded as exc:
            self._log(reqs[0], "blocked", str(exc), host=host, level=reqs[0].level or "L1")
            return [ProbeResult("blocked", str(exc)) for _ in reqs]

        results: List[Optional[ProbeResult]] = [None] * len(reqs)
        gate = threading.Barrier(len(reqs))

        def one(i: int, req: ProbeRequest) -> None:
            results[i] = self._guarded(req, skip_budget=True, gate=gate)

        threads = [threading.Thread(target=one, args=(i, r), daemon=True)
                   for i, r in enumerate(reqs)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return [r if r is not None else ProbeResult("error", "并发线程没有返回结果")
                for r in results]

    def _apply_payload_query(self, req: ProbeRequest, query: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        if not req.payload_class or not req.param_path:
            return query
        if req.payload_class in payloads.REGISTRY and payloads.REGISTRY[req.payload_class].content_type:
            # 整体替换请求体的载荷（上传/XXE/序列化流）不进 query，
            # param_path 在这里只是"给哪个字段/哪一段用"的说明
            return query
        if req.param_path.startswith(("body:", "header:")):
            return query
        name = req.param_path.split(":", 1)[1] if req.param_path.startswith("query:") else req.param_path
        value = self._payload_value(req)
        mode = payloads.REGISTRY[req.payload_class].mode if req.payload_class in payloads.REGISTRY else "replace"
        out: List[Tuple[str, str]] = []
        hit = False
        for k, v in query:
            if k == name:
                # append：原值留着，载荷接在后面（SQL 注入的字符串上下文）
                out.append((k, v + value if mode == "append" else value))
                hit = True
            else:
                out.append((k, v))
        if not hit:
            # 参数不存在时没有"原值"可接，只能整段当值
            out.append((name, value))
        return out

    def _apply_payload_body(self, req: ProbeRequest, body: Body) -> Body:
        if not req.payload_class or not req.param_path or not req.param_path.startswith("body:"):
            return body
        if req.payload_class in payloads.REGISTRY and payloads.REGISTRY[req.payload_class].content_type:
            # 已经是"载荷整体决定请求体"，不能再按 JSON 字段去改
            return body
        if body.blob is None:
            return body
        raw = self.cas.get(body.blob)
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            return body
        dotted = req.param_path.split(":", 1)[1]
        value = self._payload_value(req)
        cls = payloads.REGISTRY.get(req.payload_class or "")
        if cls is not None and cls.numeric and isinstance(value, str):
            # 负数金额必须是 JSON 数字：塞 `"-100"` 测的是"字符串被接受"。
            try:
                value = int(value)
            except ValueError:
                pass
        if not isinstance(data, dict):
            data = {}
        node = data
        parts = dotted.split(".")
        for key in parts[:-1]:
            if not isinstance(node.get(key), dict):
                node[key] = {}
            node = node[key]
        if parts[-1] == "*":
            if req.payload_class == "extra_field":
                # 批量赋值：直接补权限字段（这是模板语义，不是通用约定）
                node.update({"role": "admin", "is_admin": True})
            else:
                # 其它 body:* 载荷（如 write_marker）写进最通用的可写字段 name，
                # 回读时按"这个值出现过"归因，不依赖目标有哪些自定义字段
                node["name"] = value
        else:
            node[parts[-1]] = value
        new_raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return Body(kind="json", sha256=sha256_hex(new_raw),
                    blob=self.cas.put(new_raw, kind="request_body"), length=len(new_raw))

    def _resolve(self, canonical: CanonicalRequest, pinned: str) -> ResolvedRequest:
        headers: List[Tuple[str, str]] = []
        for h in canonical.headers:
            if h.kind == "vault_ref" and h.ref:
                value = self.vault.require(h.ref)
            elif h.kind == "derived":
                value = h.value or canonical.host
            else:
                value = h.value or ""
            headers.append((h.name, value))
        body = b""
        if canonical.body.blob:
            body = self.cas.get(canonical.body.blob)
        return ResolvedRequest(
            method=canonical.method, scheme=canonical.scheme, host=canonical.host,
            port=canonical.port, raw_path=canonical.raw_path, query=canonical.query,
            headers=tuple(headers), body=body, pinned_ip=pinned,
        )

    def _log(self, req: ProbeRequest, decision: str, reason: str, host: str = "",
             url: str = "", level: str = "", fp: str = "", detail: Optional[Dict[str, Any]] = None) -> None:
        payload: Dict[str, Any] = {
            "param_path": req.param_path,
            "payload_class": req.payload_class,
            "identity": req.identity,
            "label": req.label,
        }
        payload.update(detail or {})
        self.store.log_action(
            engagement_id=self.scope.engagement_id,
            tool="http_probe",
            decision=decision,
            reason=reason,
            host=host,
            url=url or req.url,
            level=level,
            approval_fp=fp,
            action_id=req.action_id,
            detail=payload,
        )
