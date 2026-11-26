"""报告导出：把"结论 + 它脚下的证据原文"打成一个脱离本机也能复核的包。

为什么需要一个单独的导出层：
- `verify` 只回答"manifest 链没断"，它不给读者看任何东西；
- 结论的价值全在证据上，而证据在 CAS 里是加密+内容寻址的，
  离开工作区就没法读；
- 复核的人不该信任我们的置信度，他该能自己重算：
  `sha256(canonical_request + body_sha256 + label) == evidence_id`。

导出的东西分三层，各自可独立校验：
1. `report.md` —— 人读：范围、结论、理由、指标、证据索引、复核步骤；
2. `evidence/<id>.*` —— 机器读：规范化请求、脱敏后的响应正文、元数据；
3. `manifest.json` —— 整包指纹：每个文件的 sha256 + 一个 `root_sha256`，
   读者按 `path:sha256` 排序拼行再 sha256 就能对上。

包里不放：vault 里的凭据（canonical request 只存 ref 与哈希）、未脱敏的 token。
`verify.json` 是导出时的自检结果：链是否完好、哪些证据对不上、哪些结论没绑证据。
"""
from __future__ import annotations

import hashlib
import html as _html
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import redact_bytes
from .probe import compute_evidence_id

_STATUS_CN = {"confirmed": "已确认", "hypothesis": "待验证", "refuted": "已否定",
              "pending_approval": "待审批"}
_STATUS_ORDER = {"confirmed": 0, "hypothesis": 1, "refuted": 2, "pending_approval": 3}


@dataclass
class ReportOptions:
    statuses: Tuple[str, ...] = ("confirmed", "hypothesis", "refuted")
    include_bodies: bool = True
    redact: bool = True
    max_body_bytes: int = 512 * 1024
    extra_secrets: Tuple[str, ...] = ()      # 操作者已知的敏感串，按值替换
    include_recon: bool = True
    include_all_evidence: bool = False       # 也导没挂结论的证据（侦察/基线）
    # 单文件 HTML（内联 CSS、无外部资源）：给不看 Markdown 的人一份能直接打开的东西。
    # 它和 report.md 内容同源，只是排版不同——两边数字对不上就说明有一边写错了。
    html: bool = False
    # 一次覆盖多个 engagement（同一工作区里跑过多轮时用）；空 = 只用当前工作区
    engagements: Tuple[str, ...] = ()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now(ts: Optional[str]) -> str:
    if ts:
        return ts
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write(path: str, data: bytes) -> None:
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d)
    with open(path, "wb") as fh:
        fh.write(data)


def _json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8") + b"\n"


def _load(text: Optional[str], default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def _scrub(data: bytes, opts: ReportOptions) -> bytes:
    if opts.redact:
        data = redact_bytes(data)
    for secret in opts.extra_secrets:
        if secret:
            data = data.replace(secret.encode("utf-8"), b"[REDACTED]")
    return data


def _looks_binary(body: bytes) -> bool:
    if not body:
        return False
    if b"\x00" in body[:4096]:
        return True
    try:
        body[:4096].decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


# ---------------------------------------------------------------- 证据
def verify_evidence(ws, eid: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """重算证据 id。返回 (detail, 错误原因)。错误原因空串代表一致。

    这里不用 `cas.get()`，因为它把"缺失/解密失败/哈希不符"都折成一个异常；
    导出报告要给读者看得懂的原因，所以自己按三种情况分开判。

    公开名（不带下划线）：`pta show` 要拿同一份校验过的请求去还原 PoC，
    不能自己再写一遍"读 CAS + 重算 id"，两处一旦判得不一致，
    就会出现"报告说证据有效、PoC 用的是另一份内容"。
    """
    row = ws.store.get_evidence_row(eid)
    if row is None:
        return None, "evidence_missing"

    def _read(sha: str, what: str) -> Tuple[Optional[bytes], str]:
        path = ws.cas.path_for(sha)
        if not os.path.isfile(path):
            return None, "%s_missing" % what
        with open(path, "rb") as fh:
            blob = fh.read()
        try:
            plain = ws.cas.cipher.decrypt(blob)
        except Exception:
            return None, "%s_decrypt_failed" % what
        if _sha(plain) != sha:
            return None, "%s_hash_mismatch" % what
        return plain, ""

    raw_req, err = _read(row["request_blob"], "request")
    if raw_req is None:
        return None, err
    body, err = _read(row["body_sha256"], "body")
    if body is None:
        return None, err
    try:
        req = json.loads(raw_req.decode("utf-8"))
    except Exception:
        return None, "request_not_json"
    if compute_evidence_id(req, row["body_sha256"], row["label"]) != eid:
        return None, "evidence_id_mismatch"
    return {"row": row, "request": req, "body": body}, ""


def _evidence_files(ws, eid: str, opts: ReportOptions, out_dir: str
                    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    detail, err = verify_evidence(ws, eid)
    if detail is None:
        return None, err
    row, req, body = detail["row"], detail["request"], detail["body"]
    timings = [round(t, 3) for t in ws.store.timings(eid)]

    meta = {
        "evidence_id": eid,
        "label": row["label"],
        "identity": row["identity"],
        "request": {"method": row["method"], "host": row["host"], "port": row["port"],
                    "scheme": row["scheme"], "raw_path": row["raw_path"],
                    "query": _load(row["query_json"], [])},
        "canonical_request": req,
        "status": int(row["status"]),
        "content_type": row["content_type"],
        "headers": _load(row["headers_json"], []),
        "body_sha256": row["body_sha256"],
        "body_len": int(row["body_len"]),
        "sample_count": int(row["sample_count"]),
        "timings_ms": timings,
        "param_path": row["param_path"],
        "payload_class": row["payload_class"],
        "ts_first": row["ts_first"],
        "ts_last": row["ts_last"],
        "files": {},
    }

    _write(os.path.join(out_dir, "evidence", eid + ".json"), _json(meta))
    _write(os.path.join(out_dir, "evidence", eid + ".request.json"), _json(req))
    meta["files"]["request"] = "evidence/%s.request.json" % eid

    if opts.include_bodies:
        clipped = body[:opts.max_body_bytes]
        truncated = len(body) > len(clipped)
        payload = _scrub(clipped, opts)
        if _looks_binary(payload):
            # 二进制塞 base64，仍然逐字节可校验
            import base64
            text = ("# base64 of %d bytes (truncated=%s)\n"
                    % (len(clipped), str(truncated).lower())).encode("ascii")
            name = eid + ".response.b64"
            _write(os.path.join(out_dir, "evidence", name), text + base64.b64encode(payload))
            meta["files"]["response"] = "evidence/" + name
            meta["response_encoding"] = "base64"
        else:
            name = eid + ".response.txt"
            _write(os.path.join(out_dir, "evidence", name), payload)
            meta["files"]["response"] = "evidence/" + name
            meta["response_encoding"] = "utf-8"
        meta["response_bytes"] = len(payload)
        meta["response_truncated"] = truncated
        meta["redacted"] = bool(opts.redact or opts.extra_secrets)
        _write(os.path.join(out_dir, "evidence", eid + ".json"), _json(meta))
    return meta, None


# ---------------------------------------------------------------- 结论
def _collect(ws, opts: ReportOptions,
             engagement_ids: Optional[Sequence[str]] = None
             ) -> Tuple[List[Dict[str, Any]], List[str]]:
    findings: List[Dict[str, Any]] = []
    ids: List[str] = []
    for eng in (list(engagement_ids) if engagement_ids else [ws.scope.engagement_id]):
        for row in ws.store.list_findings(eng):
            if opts.statuses and row["status"] not in opts.statuses:
                continue
            ev_ids = [str(x) for x in _load(row["evidence_ids_json"], [])]
            verdict = _load(row["verdict_json"], {})
            findings.append({
                "id": row["id"], "template_id": row["template_id"], "title": row["title"],
                "status": row["status"], "confidence": round(float(row["confidence"]), 3),
                "evidence_ids": ev_ids, "verdict": verdict,
                "overridden_by": row["overridden_by"], "created_at": row["created_at"],
                # 合并多个 engagement 时必须标明每条结论属于哪一轮，
                # 否则读者会把两轮的同名模板当成"重复上报"
                "engagement": eng,
            })
            for e in ev_ids:
                if e not in ids:
                    ids.append(e)
    findings.sort(key=lambda f: (_STATUS_ORDER.get(f["status"], 9), -f["confidence"], f["id"]))
    return findings, ids


def _metrics_table(metrics: Dict[str, Any]) -> List[str]:
    rows = ["| 指标 | 值 |", "| --- | --- |"]
    for k, v in metrics.items():
        if isinstance(v, float):
            shown = ("%.3f" % v).rstrip("0").rstrip(".")
        elif isinstance(v, (list, tuple)):
            shown = ", ".join(str(x) for x in v)
        else:
            shown = str(v)
        rows.append("| `%s` | %s |" % (k, shown.replace("|", "\\|")))
    return rows


def _render_md(ws, findings: List[Dict[str, Any]], evidence: Dict[str, Dict[str, Any]],
               verify: Dict[str, Any], opts: ReportOptions, generated_at: str,
               eng_ids: Sequence[str] = ()) -> bytes:
    scope = ws.scope
    budget = ws.budget.snapshot()
    tally: Dict[str, int] = {}
    for f in findings:
        tally[f["status"]] = tally.get(f["status"], 0) + 1

    out: List[str] = []
    title = scope.engagement_id if len(eng_ids or ()) <= 1 else \
        "%s 等 %d 轮" % (scope.engagement_id, len(eng_ids))
    out.append("# 渗透测试报告 · %s" % title)
    out.append("")
    out.append("生成时间：`%s`　导出格式：PTA report v1" % generated_at)
    out.append("")
    out.append("## 范围")
    out.append("")
    out.append("| 项 | 值 |")
    out.append("| --- | --- |")
    out.append("| 授权域 | %s |" % ", ".join("`%s`" % d for d in scope.domains))
    out.append("| 端口 | %s |" % ", ".join(str(p) for p in scope.allowed_ports))
    out.append("| 允许私网 | %s |" % ("是" if scope.allow_private else "否"))
    out.append("| 出口代理 | %s |" % ("`%s`" % scope.egress_proxy if scope.egress_proxy else "直连（仍受 DNS pin）"))
    out.append("| 到期 | `%s` |" % scope.expires_at)
    out.append("| 请求预算 | %s / %s |" % (budget.get("used"), budget.get("max")))
    out.append("")
    out.append("## 结论汇总")
    out.append("")
    out.append("共 %d 条：%s。" % (len(findings), "，".join(
        "%s %d" % (_STATUS_CN.get(k, k), v) for k, v in sorted(tally.items()))))
    out.append("")
    if findings:
        out.append("| # | 状态 | 置信度 | 模板 | 结论 | 证据 |")
        out.append("| --- | --- | --- | --- | --- | --- |")
        for i, f in enumerate(findings, 1):
            out.append("| %d | %s | %.3f | `%s` | %s | %d |" % (
                i, _STATUS_CN.get(f["status"], f["status"]), f["confidence"],
                f["template_id"], f["title"].replace("|", "\\|"), len(f["evidence_ids"])))
        out.append("")

    for i, f in enumerate(findings, 1):
        out.append("### %d. %s" % (i, f["title"]))
        out.append("")
        out.append("- 状态：**%s**　置信度：**%.3f**" % (_STATUS_CN.get(f["status"], f["status"]),
                                                        f["confidence"]))
        out.append("- 模板：`%s`　finding：`%s`" % (f["template_id"], f["id"]))
        if len(eng_ids or ()) > 1:
            # 合并多轮时每一条都要自带轮次，否则两轮的同名模板会被读成"重复上报"
            out.append("- 轮次：`%s`" % f.get("engagement", ""))
        if f.get("overridden_by"):
            out.append("- 人工改判：`%s`" % f["overridden_by"])
        verdict = f.get("verdict") or {}
        rationale = verdict.get("rationale") or "（没有留存理由）"
        out.append("- 理由：%s" % rationale)
        missing = verdict.get("missing_evidence") or []
        if missing:
            out.append("- 缺证据：%s" % ", ".join("`%s`" % m for m in missing))
        metrics = verdict.get("metrics") or {}
        if metrics:
            out.append("")
            out.extend(_metrics_table(metrics))
        out.append("")
        if f["evidence_ids"]:
            out.append("证据：")
            for e in f["evidence_ids"]:
                meta = evidence.get(e)
                if meta is None:
                    out.append("- `%s`（缺失，见 verify.json）" % e)
                    continue
                out.append("- `%s` — %s %s:%s%s，HTTP %d，%d 字节，采样 %d 次" % (
                    e, meta["request"]["method"], meta["request"]["host"],
                    meta["request"]["port"], meta["request"]["raw_path"],
                    meta["status"], meta["body_len"], meta["sample_count"]))
            out.append("")

    if verify["unbound_findings"]:
        out.append("## 未绑定证据的结论")
        out.append("")
        out.append("下面这些结论在库里没有挂任何证据 id，复核时**不应采信**"
                   "（通常是手工写入或导出前被改过）：")
        out.append("")
        for fid in verify["unbound_findings"]:
            out.append("- `%s`" % fid)
        out.append("")

    out.append("## 复核方法")
    out.append("")
    out.append("1. 每个 `evidence/<id>.json` 里有 `canonical_request`（不含凭据明文，只留 ref 与哈希）；")
    out.append("2. 取 `canonical_request` 的 JSON、`body_sha256`、`label` 三者按 "
               "`{\"req\":…,\"body\":…,\"label\":…}` 排序紧凑序列化后 sha256，应等于文件名里的 `<id>`；")
    out.append("3. `evidence/<id>.response.*` 是脱敏后的响应正文（`response_truncated` 为 true 表示只导了前 "
               "%d 字节）；" % opts.max_body_bytes)
    out.append("4. `manifest.json` 列了包里每个文件的 sha256；把 `path:sha256` 按字典序拼成行再 sha256，"
               "应等于 `root_sha256`。")
    out.append("")
    out.append("## 自检（导出时）")
    out.append("")
    out.append("| 检查 | 结果 |")
    out.append("| --- | --- |")
    out.append("| manifest 链 | %s |" % ("完好" if verify["manifest_chain"] else "断裂"))
    out.append("| 证据重算 | %d / %d 一致 |" % (verify["evidence_ok"], verify["evidence_checked"]))
    out.append("| 结论绑证据 | %d / %d |" % (verify["findings_bound"], verify["findings_checked"]))
    if verify["mismatches"]:
        out.append("")
        out.append("不一致项：")
        for m in verify["mismatches"]:
            out.append("- `%s`：%s" % (m["evidence_id"], m["reason"]))
    out.append("")
    out.append("## 边界")
    out.append("")
    out.append("- 只包含本工作区里真实发出过的请求；没有发过的假设不在报告里。")
    out.append("- 包内响应正文做过脱敏（`sk-*`、`Bearer …`，以及操作者指定的敏感串），"
               "需要原文请回工作区用 `pta evidence raw --confirm` 取。")
    out.append("- 置信度是判定函数的输出，不是概率；`refuted` 条目保留是为了说明"
               "\"为什么不是漏洞\"，不是待办。")
    out.append("")
    return ("\n".join(out) + "\n").encode("utf-8")


# ---------------------------------------------------------------- HTML
_HTML_CSS = """
:root{--ink:#111418;--muted:#5b6470;--line:#e3e7ec;--bg:#fbfcfd;
--ok:#b42318;--warn:#b54708;--dim:#667085;--wait:#175cd3}
*{box-sizing:border-box}body{margin:0;padding:40px 20px;background:var(--bg);color:var(--ink);
font:15px/1.65 -apple-system,"Segoe UI","Noto Sans SC",sans-serif}
main{max-width:900px;margin:0 auto}
h1{font-size:26px;margin:0 0 6px}h2{font-size:17px;margin:34px 0 10px;
padding-bottom:6px;border-bottom:1px solid var(--line)}
.meta{color:var(--muted);font-size:13px;margin:0 0 8px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{border-bottom:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;background:#f4f6f8}
code{font:12.5px/1.5 ui-monospace,Consolas,monospace;background:#eef1f4;
padding:1px 5px;border-radius:4px;word-break:break-all}
article{border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0;
background:#fff}
article h3{font-size:15.5px;margin:0 0 8px}
.tag{display:inline-block;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;
margin-right:8px;border:1px solid currentColor}
.s-confirmed{color:var(--ok)}.s-hypothesis{color:var(--warn)}
.s-refuted{color:var(--dim)}.s-pending_approval{color:var(--wait)}
.kv{font-size:13.5px;margin:4px 0}.kv b{font-weight:600}
ul{margin:6px 0 0 20px;padding:0}li{margin:3px 0;font-size:13.5px}
.bounds{color:var(--muted);font-size:13px}
"""


def _esc(value: Any) -> str:
    return _html.escape("" if value is None else str(value), quote=True)


def _render_html(findings: List[Dict[str, Any]], evidence: Dict[str, Dict[str, Any]],
                 verify: Dict[str, Any], opts: ReportOptions, generated_at: str,
                 eng_ids: Sequence[str], scope, budget: Dict[str, Any]) -> bytes:
    """和 report.md 同源同数的单文件 HTML。

    为什么还要第二个格式：Markdown 需要渲染器，而"发出去让人自己看"的场景里
    多一步就少一个读者。这里不引任何外部 CSS/JS/字体，双击就能开，也能直接进邮件附件。
    """
    tally: Dict[str, int] = {}
    for f in findings:
        tally[f["status"]] = tally.get(f["status"], 0) + 1

    title = scope.engagement_id if len(eng_ids) <= 1 else \
        "%s 等 %d 轮" % (scope.engagement_id, len(eng_ids))
    out: List[str] = [
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<title>渗透测试报告 · %s</title><style>%s</style></head><body><main>"
        % (_esc(title), _HTML_CSS),
        "<h1>渗透测试报告 · %s</h1>" % _esc(title),
        "<p class=\"meta\">生成时间 %s　导出格式 PTA report v1　覆盖 %d 轮　结论 %d 条</p>"
        % (_esc(generated_at), len(eng_ids), len(findings)),
    ]

    out.append("<h2>范围</h2><table><tr><th>项</th><th>值</th></tr>")
    out.append("<tr><td>授权域</td><td>%s</td></tr>"
               % _esc(", ".join(scope.domains)))
    out.append("<tr><td>端口</td><td>%s</td></tr>"
               % _esc(", ".join(str(p) for p in scope.allowed_ports)))
    out.append("<tr><td>允许私网</td><td>%s</td></tr>" % ("是" if scope.allow_private else "否"))
    out.append("<tr><td>出口代理</td><td>%s</td></tr>"
               % _esc(scope.egress_proxy or "直连（仍受 DNS pin）"))
    out.append("<tr><td>到期</td><td><code>%s</code></td></tr>" % _esc(scope.expires_at))
    out.append("<tr><td>请求预算</td><td>%s / %s</td></tr>"
               % (_esc(budget.get("used")), _esc(budget.get("max"))))
    out.append("</table>")

    out.append("<h2>结论汇总</h2><p class=\"meta\">%s</p>"
               % _esc("，".join("%s %d" % (_STATUS_CN.get(k, k), v)
                               for k, v in sorted(tally.items())) or "无"))
    if findings:
        out.append("<table><tr><th>#</th><th>状态</th><th>置信度</th><th>模板</th>"
                   "<th>结论</th><th>证据</th></tr>")
        for i, f in enumerate(findings, 1):
            st = f["status"]
            out.append("<tr><td>%d</td><td><span class=\"tag s-%s\">%s</span></td>"
                       "<td>%.3f</td><td><code>%s</code></td><td>%s</td><td>%d</td></tr>"
                       % (i, _esc(st), _esc(_STATUS_CN.get(st, st)), f["confidence"],
                          _esc(f["template_id"]), _esc(f["title"]),
                          len(f["evidence_ids"])))
        out.append("</table>")

    out.append("<h2>发现</h2>")
    for i, f in enumerate(findings, 1):
        st = f["status"]
        out.append("<article><h3>%d. %s</h3>" % (i, _esc(f["title"])))
        out.append("<p class=\"kv\"><span class=\"tag s-%s\">%s</span>"
                   "置信度 <b>%.3f</b>　模板 <code>%s</code></p>"
                   % (_esc(st), _esc(_STATUS_CN.get(st, st)), f["confidence"],
                      _esc(f["template_id"])))
        if len(eng_ids) > 1:
            out.append("<p class=\"kv\">所属轮次：<code>%s</code></p>" % _esc(f.get("engagement")))
        verdict = f.get("verdict") or {}
        out.append("<p class=\"kv\"><b>理由</b>：%s</p>"
                   % _esc(verdict.get("rationale") or "（没有留存理由）"))
        missing = verdict.get("missing_evidence") or []
        if missing:
            out.append("<p class=\"kv\"><b>缺证据</b>：%s</p>"
                       % _esc(", ".join(missing)))
        metrics = verdict.get("metrics") or {}
        if metrics:
            out.append("<table><tr><th>指标</th><th>值</th></tr>")
            for k, v in metrics.items():
                if isinstance(v, float):
                    shown = ("%.3f" % v).rstrip("0").rstrip(".")
                elif isinstance(v, (list, tuple)):
                    shown = ", ".join(str(x) for x in v)
                else:
                    shown = str(v)
                out.append("<tr><td><code>%s</code></td><td>%s</td></tr>"
                           % (_esc(k), _esc(shown)))
            out.append("</table>")
        if f["evidence_ids"]:
            out.append("<p class=\"kv\"><b>证据</b></p><ul>")
            for eid in f["evidence_ids"]:
                meta = evidence.get(eid)
                if meta is None:
                    out.append("<li><code>%s</code>（缺失，见 verify.json）</li>" % _esc(eid))
                    continue
                req = meta["request"]
                out.append("<li><code>%s</code> — %s %s:%s%s，HTTP %d，%d 字节，采样 %d 次</li>"
                           % (_esc(eid), _esc(req["method"]), _esc(req["host"]),
                              _esc(req["port"]), _esc(req["raw_path"]),
                              int(meta.get("status") or 0), int(meta.get("body_len") or 0),
                              int(meta.get("sample_count") or 0)))
            out.append("</ul>")
        out.append("</article>")

    out.append("<h2>导出自检</h2><table><tr><th>项</th><th>结果</th></tr>")
    out.append("<tr><td>manifest 链</td><td>%s</td></tr>"
               % ("完好" if verify.get("manifest_chain") else "断裂"))
    out.append("<tr><td>证据重算</td><td>%d / %d 通过</td></tr>"
               % (int(verify.get("evidence_ok") or 0), int(verify.get("evidence_checked") or 0)))
    out.append("<tr><td>结论绑定证据</td><td>%d / %d</td></tr>"
               % (int(verify.get("findings_bound") or 0),
                  int(verify.get("findings_checked") or 0)))
    out.append("</table>")
    if verify.get("mismatches"):
        out.append("<p class=\"kv\"><b>不一致项</b></p><ul>")
        for m in verify["mismatches"]:
            out.append("<li><code>%s</code>：%s</li>"
                       % (_esc(m.get("evidence_id")), _esc(m.get("reason"))))
        out.append("</ul>")

    out.append("<h2>边界</h2><ul class=\"bounds\">"
               "<li>只包含本工作区里真实发出过的请求；没有发过的假设不在报告里。</li>"
               "<li>响应正文做过脱敏（<code>sk-*</code>、<code>Bearer …</code> 与操作者指定的串），"
               "需要原文请回工作区用 <code>pta evidence raw --confirm</code> 取。</li>"
               "<li>置信度是判定函数的输出，不是概率；<code>refuted</code> 条目保留是为了说明"
               "\"为什么不是漏洞\"，不是待办。</li></ul>")
    out.append("</main></body></html>")
    return ("\n".join(out) + "\n").encode("utf-8")


# ---------------------------------------------------------------- 入口
def export_report(ws, out_dir: str, opts: Optional[ReportOptions] = None,
                  generated_at: Optional[str] = None) -> Dict[str, Any]:
    opts = opts or ReportOptions()
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    eng_ids = list(opts.engagements) or [ws.scope.engagement_id]
    findings, ev_ids = _collect(ws, opts, eng_ids)
    if opts.include_all_evidence:
        for eng in eng_ids:
            for row in ws.store.list_evidence(eng):
                if row["evidence_id"] not in ev_ids:
                    ev_ids.append(row["evidence_id"])

    evidence: Dict[str, Dict[str, Any]] = {}
    mismatches: List[Dict[str, str]] = []
    for eid in ev_ids:
        meta, err = _evidence_files(ws, eid, opts, out_dir)
        if meta is None:
            mismatches.append({"evidence_id": eid, "reason": err or "unknown"})
        else:
            evidence[eid] = meta

    unbound = [f["id"] for f in findings if not f["evidence_ids"]]
    verify = {
        "manifest_chain": bool(ws.cas.manifest.verify()),
        "evidence_checked": len(ev_ids),
        "evidence_ok": len(evidence),
        "findings_checked": len(findings),
        "findings_bound": len(findings) - len(unbound),
        "unbound_findings": unbound,
        "mismatches": mismatches,
    }
    _write(os.path.join(out_dir, "verify.json"), _json(verify))
    _write(os.path.join(out_dir, "findings.json"), _json({
        "engagement": ws.scope.engagement_id, "engagements": eng_ids,
        "generated_at": _now(generated_at),
        "findings": findings,
    }))
    _write(os.path.join(out_dir, "report.md"),
           _render_md(ws, findings, evidence, verify, opts, _now(generated_at), eng_ids))
    if opts.html:
        # 和 report.md 同源：两边数字必须一致，否则有一边写错了
        _write(os.path.join(out_dir, "report.html"),
               _render_html(findings, evidence, verify, opts, _now(generated_at),
                            eng_ids, ws.scope, ws.budget.snapshot()))

    if opts.include_recon:
        src = os.path.join(ws.root, "recon.json")
        if os.path.isfile(src):
            with open(src, "rb") as fh:
                _write(os.path.join(out_dir, "recon.json"), fh.read())

    files: List[Dict[str, Any]] = []
    for base, _dirs, names in os.walk(out_dir):
        for n in sorted(names):
            if n == "manifest.json":
                continue
            path = os.path.join(base, n)
            rel = os.path.relpath(path, out_dir).replace(os.sep, "/")
            with open(path, "rb") as fh:
                data = fh.read()
            files.append({"path": rel, "sha256": _sha(data), "bytes": len(data)})
    files.sort(key=lambda f: f["path"])
    root = _sha("\n".join("%s:%s" % (f["path"], f["sha256"]) for f in files).encode("utf-8"))

    manifest = {
        "report_format": "pta-report-v1",
        "engagement": ws.scope.engagement_id,
        "engagements": eng_ids,
        "generated_at": _now(generated_at),
        "root_sha256": root,
        "counts": {"findings": len(findings), "evidence": len(evidence),
                   "files": len(files) + 1},
        "verify": verify,
        "files": files,
    }
    _write(os.path.join(out_dir, "manifest.json"), _json(manifest))
    manifest["out_dir"] = out_dir
    return manifest
