"""证据 → PoC：把一条 finding 还原成能直接复制去打的请求。

为什么单独一层：判定层给的是"confirmed 1.00"，报告里写的是"服务端没按归属
校验"，但操作者拿去复现（写 HackerOne、给开发看、第二天重跑）时需要的是
**当时那一条请求**：方法、完整 URL（含 query 值）、身份头（含 Cookie/CSRF）、
请求体、以及"这一发到底证明了什么"。这些全在 evidence 表和 CAS 里躺着，
只是以前没有人把它拼回一份可执行的东西。

三条实现约束：
  1) 只认校验通过的证据。渲染前先跑 `report.verify_evidence`（重算
     evidence_id + CAS 解密 + 哈希比对），不一致就拒绝出 PoC —— 否则会出现
     "报告里说证据有效、复制出去的是另一份内容"。
  2) 秘密值必须解引用成明文。CanonicalRequest 里 Authorization/Cookie 存的是
     `vault_ref`，只带 ref 和 sha256；PoC 要能直接跑，得从凭证仓取明文。
     代价是 PoC 文本里含明文凭证 —— 所以 CLI 打印时提示"别粘进聊天工具"。
  3) 挑哪一发由 `verdict["roles"]` 决定，不靠猜。一条 idor 结论挂 4 条证据
     （baseline / decoy / probe / verify），拿错一条就成了"PoC 打的是正常请求"。
     旧工作区没有 roles 时按 payload_class → identity 差异 → 最后一条退化。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import report
from .models import canonical_query

#: 挑证据的优先级。"probe" 是带载荷/换了身份的那一发，最值得拿出去。
_ROLE_WANT = ("probe", "verify", "control", "decoy", "baseline")

#: 这些头由客户端按实际内容自己算，照抄进 PoC 会和浏览器/curl 打架。
_SKIP_HEADERS = ("content-length", "transfer-encoding", "connection", "accept-encoding")


class PocError(ValueError):
    """找不到结论、证据校验不过、或这条结论没挂任何证据。"""


@dataclass
class Poc:
    finding_id: str
    template_id: str
    title: str
    status: str
    confidence: float
    rationale: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    evidence_id: str = ""
    role: str = ""
    method: str = "GET"
    url: str = ""
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    body_kind: str = "none"
    response_status: int = 0
    response_type: str = ""
    response_len: int = 0
    warnings: List[str] = field(default_factory=list)

    # ---------- 派生属性 ----------
    @property
    def host(self) -> str:
        from urllib.parse import urlsplit

        return urlsplit(self.url).hostname or ""

    @property
    def port(self) -> int:
        from urllib.parse import urlsplit

        sp = urlsplit(self.url)
        if sp.port:
            return sp.port
        return 443 if sp.scheme == "https" else 80

    @property
    def scheme(self) -> str:
        return "https" if self.url.startswith("https://") else "http"

    @property
    def target(self) -> str:
        from urllib.parse import urlsplit

        sp = urlsplit(self.url)
        return (sp.path or "/") + (("?" + sp.query) if sp.query else "")

    @property
    def binary_body(self) -> bool:
        """请求体是不是「不能安全地塞进 shell 单引号」的那类（反序列化/上传）。"""
        if not self.body:
            return False
        if self.body_kind in ("raw",):
            try:
                self.body.decode("utf-8")
            except UnicodeDecodeError:
                return True
        return False

    def text_body(self) -> str:
        return self.body.decode("utf-8", "replace")


# ---------------------------------------------------------------- 载入
def _as_dict(row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()} if row is not None else {}


def _role_of(roles: Dict[str, str], eid: str) -> str:
    return (roles.get(eid) or "").split("+")[0]


def pick_evidence(ws, finding: Dict[str, Any]) -> Tuple[str, str]:
    """挑出「证明问题的那一发」。返回 (evidence_id, role)。"""
    eids = [e for e in (finding.get("evidence_ids") or []) if e]
    if not eids:
        return "", ""
    roles = ((finding.get("verdict") or {}).get("roles") or {}) if isinstance(
        finding.get("verdict"), dict) else {}

    have = {eid: _role_of(roles, eid) for eid in eids}
    for want in _ROLE_WANT:
        for eid, role in have.items():
            if role == want:
                return eid, role

    # 旧工作区：roles 没落库（这一层是 P2.4 才加的）。按语义退化，并在
    # Poc.warnings 里说明"角色是推出来的"，别让人以为是精确的。
    rows = [(eid, ws.store.get_evidence_row(eid)) for eid in eids]
    for eid, row in rows:
        if row is not None and row["payload_class"]:
            return eid, "probe?"
    if rows and rows[0][1] is not None:
        base_identity = rows[0][1]["identity"]
        for eid, row in rows[1:]:
            if row is not None and row["identity"] != base_identity:
                return eid, "probe?"
    return eids[-1], "?"


def _resolve_headers(ws, req: Dict[str, Any], warnings: List[str]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for h in req.get("headers") or []:
        name = h.get("name") or ""
        low = name.lower()
        if not name or low in _SKIP_HEADERS:
            continue
        kind = h.get("kind") or "literal"
        value = h.get("value")
        if kind in ("vault_ref", "vault"):
            ref = h.get("ref") or ""
            try:
                value = ws.vault.get(ref)
            except KeyError:
                warnings.append("凭证 %s 已被删除，PoC 里这一条头是空的" % ref)
                continue
        if value is None:
            continue
        if name == name.lower():
            # 凭证仓里的键名是小写的（`cred/bob/cookie`）。照原样印出来能跑，
            # 但复制给人看时 `cookie:` 看着像个拼写错误，统一成规范大小写。
            name = "-".join(part.capitalize() for part in name.split("-"))
        out.append((name, value))
    return out


def _url_of(req: Dict[str, Any]) -> str:
    scheme = req.get("scheme") or "http"
    host = req.get("host") or ""
    port = int(req.get("port") or (443 if scheme == "https" else 80))
    path = req.get("raw_path") or "/"
    query = canonical_query(tuple((str(a), str(b)) for a, b in (req.get("query") or [])))
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    hostport = host if default_port else "%s:%d" % (host, port)
    return "%s://%s%s%s" % (scheme, hostport, path, ("?" + query) if query else "")


def load(ws, finding_id: Optional[str] = None, last: bool = False) -> Poc:
    """从工作区读一条结论，把它的关键证据还原成 PoC。"""
    eng = ws.scope.engagement_id
    row = None
    if finding_id:
        row = ws.store.get_finding(finding_id)
        if row is None:
            raise PocError("没有这条结论：%s（用 `pta state` 或 `pta report` 看 id）" % finding_id)
    elif last:
        row = ws.store.latest_finding(eng)
        if row is None:
            raise PocError("工作区里还没有任何结论：先跑 `pta run`")
    else:
        raise PocError("要么给 finding_id，要么加 --last")

    finding = _as_dict(row)
    finding["evidence_ids"] = json.loads(finding.get("evidence_ids_json") or "[]")
    finding["verdict"] = json.loads(finding.get("verdict_json") or "{}")

    eid, role = pick_evidence(ws, finding)
    if not eid:
        raise PocError("这条结论没有挂证据（可能只到 pending_approval/预算耗尽）：%s"
                       % finding.get("id"))

    detail, err = report.verify_evidence(ws, eid)
    if detail is None:
        raise PocError("证据 %s 校验不过（%s）：拒绝从一份对不上的证据出 PoC" % (eid, err))
    req = detail["request"]

    warnings: List[str] = []
    if role.endswith("?"):
        warnings.append("这条结论是旧版本落的，没有角色表；按载荷/身份差异推出来的那一发")

    # detail["body"] 是**响应**体（row["body_sha256"] 那条）。PoC 要的是**请求**体，
    # 它在 canonical request 的 body.blob 里。这两个混了就会把服务端返回的 JSON
    # 当成 --data-binary 发出去，复制出去的那条 curl 直接变成另一个请求。
    req_body = b""
    blob = ((req.get("body") or {}).get("blob") or "")
    if blob:
        try:
            req_body = ws.cas.get(blob)
        except KeyError:
            warnings.append("请求体 blob %s 不在 CAS 里，PoC 里没有请求体" % blob[:12])

    ev = _as_dict(detail["row"])
    poc = Poc(
        finding_id=finding.get("id") or "",
        template_id=finding.get("template_id") or "",
        title=finding.get("title") or "",
        status=finding.get("status") or "",
        confidence=float(finding.get("confidence") or 0.0),
        rationale=str((finding.get("verdict") or {}).get("rationale") or ""),
        metrics=dict((finding.get("verdict") or {}).get("metrics") or {}),
        evidence_id=eid,
        role=role,
        method=req.get("method") or "GET",
        url=_url_of(req),
        headers=_resolve_headers(ws, req, warnings),
        body=req_body,
        body_kind=((req.get("body") or {}).get("kind") or "none"),
        response_status=int(ev.get("status") or 0),
        response_type=ev.get("content_type") or "",
        response_len=int(ev.get("body_len") or 0),
        warnings=warnings,
    )
    return poc


# ---------------------------------------------------------------- 渲染
def _bash_q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _ps_q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def render_curl(poc: Poc, body_path: Optional[str] = None, powershell: bool = False) -> str:
    q = _ps_q if powershell else _bash_q
    cont = " `\n  " if powershell else " \\\n  "
    parts = ["curl.exe -sS -i -X %s %s" % (poc.method, q(poc.url))]
    for name, value in poc.headers:
        parts.append("-H %s" % q("%s: %s" % (name, value)))
    if poc.body:
        if poc.binary_body:
            parts.append("--data-binary @%s" % (body_path or "POC_BODY.bin"))
        else:
            parts.append("--data-binary %s" % q(poc.text_body()))
    return cont.join(parts)


def render_raw(poc: Poc) -> str:
    from urllib.parse import urlsplit

    sp = urlsplit(poc.url)
    default_port = (poc.scheme == "http" and sp.port in (None, 80)) or \
                   (poc.scheme == "https" and sp.port in (None, 443))
    host = sp.hostname or ""
    if not default_port:
        host = "%s:%d" % (host, poc.port)
    lines = ["%s %s HTTP/1.1" % (poc.method, poc.target), "Host: %s" % host]
    lines += ["%s: %s" % (k, v) for k, v in poc.headers if k.lower() != "host"]
    body = poc.body
    if body:
        lines.append("Content-Length: %d" % len(body))
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head + body.decode("utf-8", "replace")


def render_python(poc: Poc) -> str:
    head = {"Accept": "*/*"}
    for name, value in poc.headers:
        head[name] = value
    body_expr = "None"
    if poc.body:
        if poc.binary_body:
            body_expr = "open('POC_BODY.bin', 'rb').read()"
        else:
            body_expr = repr(poc.text_body())
    conn = "HTTPSConnection" if poc.scheme == "https" else "HTTPConnection"
    return (
        "import http.client\n\n"
        "conn = http.client.%s(%r, %d, timeout=20)\n"
        "conn.request(%r, %r, body=%s, headers=%r)\n"
        "r = conn.getresponse()\n"
        "print(r.status, r.getheader('content-type'))\n"
        "print(r.read().decode('utf-8', 'replace'))\n"
        "conn.close()\n"
        % (conn, poc.host, poc.port, poc.method, poc.target, body_expr, head)
    )


def render(poc: Poc, as_format: str = "curl", body_path: Optional[str] = None) -> str:
    fmt = (as_format or "curl").lower()
    if fmt in ("curl", "bash"):
        return render_curl(poc, body_path=body_path)
    if fmt in ("powershell", "pwsh", "ps"):
        return render_curl(poc, body_path=body_path, powershell=True)
    if fmt == "raw":
        return render_raw(poc)
    if fmt in ("python", "py"):
        return render_python(poc)
    raise PocError("不认识的格式 %r（curl / powershell / raw / python）" % as_format)


# ---------------------------------------------------------------- 说明
def explain(poc: Poc) -> List[str]:
    """「这一发证明了什么」—— 结论 + 请求 + 响应特征 + 指标。"""
    out = [
        "结论：%s  %s  [%s %.2f]" % (poc.template_id, poc.title, poc.status, poc.confidence),
        "证据：%s（角色 %s，哈希重算一致）" % (poc.evidence_id, poc.role or "-"),
        "请求：%s %s" % (poc.method, poc.url),
    ]
    if poc.headers:
        out.append("头部：%s" % "，".join(k for k, _ in poc.headers))
    if poc.body:
        out.append("请求体：%d 字节（%s）" % (len(poc.body), poc.body_kind))
    out.append("响应：%d %s %d 字节（这是当时录到的，不是现在重打的）"
               % (poc.response_status, poc.response_type or "-", poc.response_len))
    if poc.rationale:
        out.append("判定：%s" % poc.rationale)
    if poc.metrics:
        flat = "，".join("%s=%s" % (k, _brief(v)) for k, v in sorted(poc.metrics.items()))
        out.append("指标：%s" % flat)
    for warn in poc.warnings:
        out.append("注意：%s" % warn)
    return out


def _brief(v: Any) -> str:
    if isinstance(v, float):
        return "%.3f" % v
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)[:80]
    return str(v)


def save_body(poc: Poc, path: str) -> str:
    with open(path, "wb") as fh:
        fh.write(poc.body)
    return path
