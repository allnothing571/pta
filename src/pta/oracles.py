"""Oracle 库（P0 三个）。

契约：纯函数、只读证据、确定性、证据不足返回 passed=False/confidence=0.0/missing_evidence。
"""
from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit

from .cas import Cas
from .models import Verdict, strip_dynamic
from .store import Store


@dataclass(frozen=True)
class Observation:
    role: str                 # baseline | probe | control
    evidence_id: str
    identity: str
    method: str
    url: str
    status: int
    content_type: Optional[str]
    body_sha256: str
    body_len: int
    body: bytes = field(repr=False, default=b"")
    headers: Dict[str, str] = field(default_factory=dict)   # 键已小写
    # 同一请求的多次采样耗时（ms，按采样顺序）；时间盲注只看它，不看响应体
    timings: Tuple[float, ...] = ()
    # OOB 回连专用（普通响应为空）
    source_ip: str = ""
    protocol: str = ""
    token: str = ""
    # 并发突发专用：同一请求同时发 N 发时，每一发的状态码（按发出顺序）。
    # 普通探测为空元组——那时"发了几次"由 timings 表达，语义不同不能混用。
    burst_statuses: Tuple[int, ...] = ()

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def load_observations(store: Store, cas: Cas, engagement_id: str, label: str,
                      roles: Optional[Dict[str, str]] = None) -> List[Observation]:
    """按 label 取证据，roles 把 evidence_id -> role 映射上。"""
    out: List[Observation] = []
    for row in store.list_evidence(engagement_id, label):
        body = cas.get(row["body_sha256"]) if cas.exists(row["body_sha256"]) else b""
        role = (roles or {}).get(row["evidence_id"], "other")
        out.append(Observation(
            role=role,
            evidence_id=row["evidence_id"],
            identity=row["identity"],
            method=row["method"],
            url="%s://%s:%d%s" % (row["scheme"], row["host"], row["port"], row["raw_path"]),
            status=int(row["status"]),
            content_type=row["content_type"],
            body_sha256=row["body_sha256"],
            body_len=int(row["body_len"]),
            body=body,
            headers=_header_dict(row["headers_json"]),
            timings=tuple(store.timings(row["evidence_id"])),
        ))
    return out


def _header_dict(raw: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for name, value in json.loads(raw or "[]"):
            key = str(name).strip().lower()
            if key and key not in out:
                out[key] = str(value)
    except (ValueError, TypeError):
        return {}
    return out


def _by_role(obs: Sequence[Observation], role: str) -> List[Observation]:
    """按角色取证据。角色可以是 `baseline+verify` 这种复合形式：

    "写后回读"里如果写入没生效，回读响应与基线逐字节相同，内容寻址会把它们
    去重成同一条证据——这时它同时承担两个角色，必须两个角色都能取到它。
    """
    return [o for o in obs if o.role == role or role in str(o.role).split("+")]


class Oracle:
    name = "abstract"
    min_level = "L0"

    @dataclass
    class Args:
        pass

    def run(self, obs: Sequence[Observation], args: "Oracle.Args") -> Verdict:
        raise NotImplementedError


def _jaccard(a: bytes, b: bytes) -> float:
    sa = set(re.findall(rb"[A-Za-z0-9_]+", strip_dynamic(a)))
    sb = set(re.findall(rb"[A-Za-z0-9_]+", strip_dynamic(b)))
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / float(len(sa | sb))


def _len_ratio(a: bytes, b: bytes) -> float:
    la, lb = len(a), len(b)
    if la == 0 and lb == 0:
        return 1.0
    return min(la, lb) / float(max(la, lb))


def _sim(a: bytes, b: bytes) -> float:
    """0.6*词集合重合 + 0.4*长度比。

    和 IDOR 用的同一把尺子：只要"内容变了"，无论变多变小都会被拉开。
    反过来，两份响应哪怕字面不同（时间戳、CSRF token），只要词集合与长度
    接近，相似度仍然很高 —— 布尔盲注最怕的就是把"渲染抖动"当成"结果集变了"。
    """
    return 0.6 * _jaccard(a, b) + 0.4 * _len_ratio(a, b)


class DifferentialObjectAccess(Oracle):
    """IDOR：两个身份拿同一对象，返回内容高度相似且都 200。

    confidence = 0.6*jaccard + 0.4*len_ratio，阈值 min_similarity。
    关键反证：如果 probe 身份拿到 401/403，或内容与 baseline 差异大，一律不算。
    """

    name = "differential_object_access"
    min_level = "L1"

    @dataclass
    class Args:
        min_similarity: float = 0.92
        success_status: Tuple[int, ...] = (200,)

    def run(self, obs, args):
        base = _by_role(obs, "baseline")
        probe = _by_role(obs, "probe")
        if not base or not probe:
            return Verdict(False, 0.0, {}, "缺少 baseline 或 probe 证据",
                           ("baseline", "probe") if not base else ("probe",))
        b, p = base[0], probe[0]
        if b.identity == p.identity:
            return Verdict(False, 0.0, {"reason": "same_identity"},
                           "两个观察来自同一身份，无法证明越权")
        if p.status not in args.success_status:
            return Verdict(False, 0.0, {"probe_status": p.status}, "probe 未成功返回受保护对象")
        if b.status not in args.success_status:
            return Verdict(False, 0.0, {"baseline_status": b.status}, "baseline 不成立，缺少对照")
        jac = _jaccard(b.body, p.body)
        ratio = _len_ratio(b.body, p.body)
        sim = 0.6 * jac + 0.4 * ratio
        passed = sim >= args.min_similarity

        # 负对照：读一个不可能存在的对象。如果它也给出同样的内容，
        # 说明服务端根本没按 id 查——那"两个人看到同一份"就不是越权，是公开资源。
        decoy = _by_role(obs, "decoy")
        d = decoy[0] if decoy else None
        if passed and d is not None and d.status in args.success_status:
            d_sim = 0.6 * _jaccard(b.body, d.body) + 0.4 * _len_ratio(b.body, d.body)
            if d_sim >= args.min_similarity:
                return Verdict(
                    False, 0.35,
                    {"jaccard": round(jac, 4), "len_ratio": round(ratio, 4),
                     "similarity": round(sim, 4), "threshold": args.min_similarity,
                     "decoy_status": d.status, "decoy_similarity": round(d_sim, 4)},
                    "不存在的对象也返回了同样的内容（相似度 %.3f）：响应与对象 id 无关，"
                    "据此判越权不成立" % d_sim,
                )

        metrics = {"jaccard": round(jac, 4), "len_ratio": round(ratio, 4),
                   "similarity": round(sim, 4), "threshold": args.min_similarity}
        if d is not None:
            metrics["decoy_status"] = d.status
        conf = sim if passed else min(sim, 0.5)
        return Verdict(
            passed, conf, metrics,
            "内容相似度 %.3f（阈值 %.2f）" % (sim, args.min_similarity),
        )


_ERROR_SIGNATURES = (
    ("sqlstate", re.compile(rb"SQLSTATE\[[0-9A-Z]{5}\]"), 0.95),
    ("mysql", re.compile(rb"(?i)(mysql_|you have an error in your sql syntax|MySqli?)"), 0.90),
    ("pgsql", re.compile(rb"(?i)(pg_query|PostgreSQL.*ERROR|unterminated quoted string)"), 0.90),
    ("oracle", re.compile(rb"(?i)(ORA-[0-9]{4,5}|oracle\.jdbc)"), 0.95),
    ("mssql", re.compile(rb"(?i)(Microsoft OLE DB|SqlException|Unclosed quotation mark)"), 0.90),
    # SQLite 是嵌入式应用的默认库（Django 开发库、桌面端、移动端），它自己的错误文案
    # 很稳定（`sqlite3.OperationalError: near "'": syntax error`），值得单独一条。
    ("sqlite", re.compile(rb"(?i)(sqlite3?\.(OperationalError|ProgrammingError)|"
                          rb"no such column|no such table|unrecognized token)"), 0.90),
    ("generic", re.compile(rb"(?i)(syntax error|unexpected token|internal server error)"), 0.45),
)


class ErrorSignatureMatch(Oracle):
    """报错型注入：probe 出现 baseline 没有的数据库错误签名。"""

    name = "error_signature_match"
    min_level = "L1"

    @dataclass
    class Args:
        min_weight: float = 0.85

    def run(self, obs, args):
        base = _by_role(obs, "baseline")
        probe = _by_role(obs, "probe")
        if not probe:
            return Verdict(False, 0.0, {}, "缺少 probe 证据", ("probe",))
        base_body = base[0].body if base else b""
        hits: List[Tuple[str, float]] = []
        for name, pat, weight in _ERROR_SIGNATURES:
            if pat.search(probe[0].body) and not pat.search(base_body):
                hits.append((name, weight))
        if not hits:
            return Verdict(False, 0.0, {"signatures": []}, "probe 未出现 baseline 中没有的错误签名")
        best = max(hits, key=lambda x: x[1])
        passed = best[1] >= args.min_weight
        return Verdict(passed, best[1], {"signatures": hits, "best": best[0]},
                       "命中 %s 签名，权重 %.2f" % (best[0], best[1]))


class BooleanResponseSplit(Oracle):
    """布尔盲注：`1=1` 与 `1=2` 两份响应被"掰开"，而 `1=1` 又与基线一致。

    三份证据缺一不可，判的是三角关系，不是单份响应长什么样：

        baseline  ≈  probe_true      （同一页面，说明 payload 没把页面打坏）
        baseline  ≉  probe_false     （假条件让结果集变了）
        probe_true ≉ probe_false     （差异确实来自布尔条件）

    常见假阳性在这里被挡掉：
    - 服务器把参数当字符串忽略 → 两份响应完全一样（相似度 ≥ min_similarity_same）；
    - 单引号直接 500 / WAF 403 → 两个条件都没拿到正常响应；
    - 差异方向相反（假条件更像基线）→ 说明不是布尔注入，而是别的分流逻辑。
    """

    name = "boolean_response_split"
    min_level = "L1"

    @dataclass
    class Args:
        min_similarity_same: float = 0.90
        max_similarity_diff: float = 0.55
        success_status: Tuple[int, ...] = (200,)

    def run(self, obs: Sequence[Observation], args: "BooleanResponseSplit.Args") -> Verdict:
        base = _by_role(obs, "baseline")
        t = _by_role(obs, "probe_true")
        f = _by_role(obs, "probe_false")
        missing = tuple(n for n, got in
                        (("baseline", base), ("probe_true", t), ("probe_false", f)) if not got)
        if missing:
            return Verdict(False, 0.0, {}, "缺少 %s 证据" % " / ".join(missing), missing)

        b, ot, of = base[0], t[0], f[0]
        rejected = [o.status for o in (ot, of) if o.status in (401, 403, 429)]
        if rejected:
            return Verdict(False, 0.0, {"rejected_status": rejected},
                           "注入请求被拒绝（%d），无法读布尔差异" % rejected[0])
        normal = [o for o in (ot, of) if o.status in args.success_status]
        if not normal:
            return Verdict(False, 0.10, {"true_status": ot.status, "false_status": of.status},
                           "两个条件都没拿到正常响应（%d / %d）" % (ot.status, of.status))

        sim_tf = _sim(ot.body, of.body)
        sim_tb = _sim(b.body, ot.body)
        sim_fb = _sim(b.body, of.body)
        metrics = {
            "similarity_true_false": round(sim_tf, 4),
            "similarity_true_base": round(sim_tb, 4),
            "similarity_false_base": round(sim_fb, 4),
            "len_true": len(ot.body), "len_false": len(of.body), "len_base": len(b.body),
            "threshold_same": args.min_similarity_same,
            "threshold_diff": args.max_similarity_diff,
        }

        if sim_tf >= args.min_similarity_same:
            return Verdict(False, 0.15, metrics,
                           "1=1 与 1=2 的响应几乎一致（%.3f），参数没有进入查询" % sim_tf)
        if sim_tb < args.max_similarity_diff:
            return Verdict(False, 0.20, metrics,
                           "真条件就偏离基线（%.3f），payload 把页面打坏了，不能当布尔差异" % sim_tb)
        if sim_fb > sim_tb:
            return Verdict(False, 0.25, metrics,
                           "差异方向相反：假条件更像基线（%.3f > %.3f）" % (sim_fb, sim_tb))

        strong = sim_tb >= 0.95 and sim_tf <= 0.35
        conf = 0.93 if strong else 0.88
        return Verdict(True, conf, metrics,
                       "真条件与基线一致（%.3f），假条件偏离（真/假 %.3f）"
                       % (sim_tb, sim_tf))


FILE_SIGS = (
    ("git_config", re.compile(rb"\[core\]\s*\n\s*repositoryformatversion"), 0.95),
    ("git_head", re.compile(rb"^ref:\s*refs/heads/"), 0.95),
    ("env_file", re.compile(rb"(?m)^[A-Z0-9_]{3,}=.{0,200}$"), 0.60),
    ("sql_dump", re.compile(rb"(?i)(CREATE TABLE|INSERT INTO) `?\w+`?"), 0.80),
    ("aws_cred", re.compile(rb"AKIA[0-9A-Z]{16}"), 0.95),
    ("php_source", re.compile(rb"<\?php"), 0.90),
    # 路径穿越专用：这些是"读到系统文件"的正特征
    ("passwd_file", re.compile(rb"(?m)^root:[^:\r\n]*:0:0:"), 0.95),
    ("shadow_file", re.compile(rb"(?m)^root:[^\s:]{8,}:\d+:"), 0.85),
    ("win_ini", re.compile(rb"(?im)^\s*\[(extensions|fonts|mci extensions)\]"), 0.85),
    ("win_boot", re.compile(rb"(?i)\[boot loader\]"), 0.90),
    ("dir_listing", re.compile(rb"(?i)<title>\s*Index of /|Directory listing for /"), 0.85),
    # 框架把内部堆栈吐在错误页上：类名、包路径、源码行号、SQL 片段全在里面。
    # 这不是「一个 JSON 接口」，这是「服务器把内部结构告诉了你」——真实靶场
    # （WebGoat/Spring）上正是靠这一条才没被 json_api 反特征洗掉。
    ("stack_trace", re.compile(
        rb"(?i)(Traceback \(most recent call last\)"
        rb"|java\.lang\.[A-Z]\w*(Exception|Error)"
        rb"|\"trace\"\s*:\s*\"(java|org|com|net)\."
        rb"|\bat\s+[\w.$]+\.(java|kt|scala):\d+\)"
        rb"|\bat\s+[A-Z][\w.]*\s+\([\w./\\-]+\.(js|ts|py):\d+:\d+\)"
        rb"|Stack\s*Trace:\s*\r?\n\s*at\s+[A-Z])"), 0.95),
)
FILE_NEG = (
    ("html_doc", re.compile(rb"(?i)<!doctype html|<html[\s>]"), -0.60),
    ("spa_shell", re.compile(rb"(?i)<div id=\"(root|app)\"></div>"), -0.70),
    ("json_api", re.compile(rb'^\s*\{\s*"'), -0.50),
    # 路径穿越的典型假阳性：404 页面、把路径原样回显的错误页
    ("not_found_text", re.compile(rb"(?i)\b(404|not\s+found|page\s+not\s+found)\b"), -0.45),
    ("error_path_echo", re.compile(
        rb"(?i)(no such file|file not exist|invalid path|\.\./\.\./|%2e%2e%2f)[^\n]{0,80}"
        rb"(error|denied|invalid|not exist)"), -0.50),
)


CONTAINER_NEG = frozenset({"html_doc", "spa_shell", "json_api"})

# 命中哪一类强特征，报告上就该写哪一类。模板的标题只是个兜底（"敏感构建产物/凭据文件
# 暴露"），真命中 Java 堆栈时还照抄，用户会把一份堆栈当凭据泄露去处置。
_HIT_TITLES = {
    "stack_trace": "报错页泄露堆栈（框架/版本/内部路径）",
    "dir_listing": "目录列表可浏览（文件清单暴露）",
    "passwd_file": "系统账号文件可读（/etc/passwd 片段）",
    "env_file": "环境变量文件可读（KEY=VALUE）",
    "ssh_key": "私钥文件可读",
    "phpinfo": "phpinfo 页面暴露",
    "db_dump": "数据库导出文件可读",
    "backup_file": "备份文件可读",
}


class FileSignatureMatch(Oracle):
    """敏感文件泄露：正特征权重高，反特征（SPA 回退/HTML 壳/404 页）抵消。

    强正特征（≥0.85，如 passwd 行、目录列表）命中时，不再因为"外面包了一层 HTML"
    而扣分——真实文件经常被框架套上模板；只有弱特征（如 .env 的 KEY=VALUE）才怕 HTML 壳。
    """

    name = "file_signature_match"
    min_level = "L0"

    @dataclass
    class Args:
        min_confidence: float = 0.85
        expected: Optional[str] = None   # 指定必须命中的签名

    def run(self, obs, args):
        probe = _by_role(obs, "probe")
        if not probe:
            return Verdict(False, 0.0, {}, "缺少 probe 证据", ("probe",))
        o = probe[0]
        score = 0.0
        hits: List[str] = []
        for name, pat, weight in FILE_SIGS:
            if pat.search(o.body):
                score += weight
                hits.append(name)
        strong = max([w for n, p, w in FILE_SIGS if n in hits] or [0.0]) >= 0.85
        neg: List[str] = []
        for name, pat, weight in FILE_NEG:
            if strong and name in CONTAINER_NEG:
                continue
            if pat.search(o.body):
                score += weight
                neg.append(name)
        if args.expected and args.expected not in hits:
            return Verdict(False, 0.0, {"hits": hits, "neg": neg},
                           "未命中期望签名 %s" % args.expected)
        conf = max(0.0, min(score, 0.98))
        passed = conf >= args.min_confidence and hits
        title = ""
        if passed:
            # 取权重最高的那个命中当标题；认不出的签名就直说命中的名字，不假装它是别的东西。
            top = max(hits, key=lambda n: max(w for m, p, w in FILE_SIGS if m == n))
            title = _HIT_TITLES.get(top) or ("可读的敏感内容（命中 %s）" % top)
        return Verdict(bool(passed), conf if passed else min(conf, 0.5),
                       {"hits": hits, "neg": neg, "score": round(score, 3)},
                       "正特征 %d 个、反特征 %d 个" % (len(hits), len(neg)),
                       title=title)


class OobCallbackReceived(Oracle):
    """带外回连判定。只认我们自己发出的 token 触发的回连。"""

    class Args:
        def __init__(self, min_callbacks: int = 1, require_http: bool = False,
                     our_egress_ips: Tuple[str, ...] = (), max_self_trigger_ratio: float = 0.0):
            self.min_callbacks = min_callbacks
            self.require_http = require_http
            self.our_egress_ips = our_egress_ips
            self.max_self_trigger_ratio = max_self_trigger_ratio

    name = "oob_callback_received"
    minimum_level = "L2"

    def run(self, obs: Sequence[Observation], args: "OobCallbackReceived.Args") -> Verdict:
        callbacks = _by_role(obs, "callback")
        if not callbacks:
            return Verdict(False, 0.0, {"callbacks": 0},
                           "没有收到带外回连", missing_evidence=["callback:*"])

        ours = set(args.our_egress_ips)
        genuine = [o for o in callbacks if o.source_ip not in ours]
        self_trig = len(callbacks) - len(genuine)
        metrics = {"callbacks": len(callbacks), "genuine": len(genuine),
                   "self_trigger": self_trig,
                   "protocols": sorted({o.protocol or "http" for o in genuine})}
        if not genuine:
            return Verdict(False, 0.0, metrics, "回连全部来自我方出口 IP（自触发）")
        ratio = float(self_trig) / len(callbacks)
        if ratio > args.max_self_trigger_ratio and self_trig:
            return Verdict(False, 0.2, metrics, "自触发占比 %.0f%% 超过阈值" % (ratio * 100))

        http = [o for o in genuine if (o.protocol or "http") == "http"]
        if args.require_http and not http:
            return Verdict(False, 0.30, metrics, "只有 DNS 回连，模板要求 HTTP 证据")
        if len(genuine) < args.min_callbacks:
            return Verdict(False, 0.30, metrics,
                           "有效回连 %d 少于要求 %d" % (len(genuine), args.min_callbacks))
        conf = 0.95 if http else 0.75
        return Verdict(True, conf, metrics,
                       "有效回连 %d 条（HTTP %d / DNS %d）" % (len(genuine), len(http),
                                                              len(genuine) - len(http)))


class RedirectTargetMatch(Oracle):
    """开放重定向：3xx 且 Location 指向我们指定的外部 host。

    只看"跳到了哪"，不跟过去（follow_redirects 默认关，避免把请求带到范围外）。
    相对路径 / 同站跳转一律不算——那是正常路由行为。
    """

    name = "redirect_target_match"
    min_level = "L1"

    @dataclass
    class Args:
        expected_host: Optional[str] = None   # 载荷注入的目标 host，通常是 redirect.test
        allow_suffix: bool = True             # 允许 sub.expected_host
        min_confidence: float = 0.80

    def run(self, obs, args):
        probe = _by_role(obs, "probe")
        if not probe:
            return Verdict(False, 0.0, {}, "缺少 probe 证据", ("probe",))
        o = probe[0]
        location = (o.headers.get("location") or "").strip()
        metrics = {"status": o.status, "location": location[:300]}
        if not location:
            return Verdict(False, 0.0, metrics, "响应没有 Location 头", ("probe:location",))
        if not (300 <= o.status < 400):
            return Verdict(False, 0.0, metrics, "响应 %d 不是重定向" % o.status)
        host = _location_host(location)
        if not host:
            return Verdict(False, 0.0, metrics, "Location 是相对路径，不构成开放重定向")
        metrics["target_host"] = host
        if args.expected_host:
            want = args.expected_host.lower()
            exact = host == want
            suffix = args.allow_suffix and host.endswith("." + want)
            if not (exact or suffix):
                return Verdict(False, 0.0, metrics,
                               "Location 指向 %s，不是注入目标 %s" % (host, want))
            conf = 0.90 if exact else 0.85
            passed = conf >= args.min_confidence
        else:
            # 没给目标就只认"跨站"，置信度天然低一档，只够 hypothesis
            same_host = host == (urlsplit(o.url).hostname or "").lower()
            if same_host:
                return Verdict(False, 0.0, metrics, "跳转仍在同站，不构成开放重定向")
            conf, passed = 0.75, True
        return Verdict(passed, conf if passed else min(conf, 0.5), metrics,
                       "3xx 跳到外部 host %s" % host)


def _location_host(location: str) -> str:
    """只接受绝对/协议相对的 Location；相对路径返回空串（那是站内路由）。"""
    try:
        parts = urlsplit(location)
    except ValueError:
        return ""
    if not parts.netloc:
        return ""
    return (parts.hostname or "").lower()


class JwtAcceptanceCheck(Oracle):
    """JWT 信任边界：签名被破坏的 token 是否仍被当成有效身份。

    判定只回答一件事——伪造 token（alg=none 或空签名）换来的响应，
    是否与同一身份用合法 token 拿到的响应等价。等价即证明服务端没在验签。
    """

    name = "jwt_acceptance_check"
    min_level = "L1"

    @dataclass
    class Args:
        min_similarity_ok: float = 0.90    # 与 baseline 等价 → 接受伪造
        max_similarity_deny: float = 0.50  # 差异这么大 → 不是同一个身份的数据
        success_status: Tuple[int, ...] = (200,)

    def run(self, obs, args):
        probe = _by_role(obs, "probe")
        if not probe:
            return Verdict(False, 0.0, {}, "缺少 probe 证据", ("probe",))
        p = probe[0]
        metrics: Dict[str, Any] = {"probe_status": p.status}
        if p.status in (401, 403):
            return Verdict(False, 0.0, metrics, "伪造 token 被拒（%d）" % p.status)
        if p.status not in args.success_status:
            return Verdict(False, 0.0, metrics, "伪造 token 未取得受保护资源（%d）" % p.status)

        base = _by_role(obs, "baseline")
        if not base:
            # 只有伪造请求成功：说明签名没拦住，但没有对照就无法证明"身份被顶替"
            return Verdict(False, 0.60, metrics,
                           "伪造 token 返回 %d，但缺少同身份对照，只能算 hypothesis" % p.status,
                           ("baseline",))
        b = base[0]
        metrics["baseline_status"] = b.status
        if b.status not in args.success_status:
            return Verdict(False, 0.0, metrics, "baseline 本身就不可用（%d）" % b.status)
        sim = 0.6 * _jaccard(b.body, p.body) + 0.4 * _len_ratio(b.body, p.body)
        metrics["similarity"] = round(sim, 4)
        if sim >= args.min_similarity_ok:
            return Verdict(True, 0.90, metrics,
                           "签名无效的 token 拿到与合法身份等价的数据（相似度 %.3f）" % sim)
        if sim <= args.max_similarity_deny:
            return Verdict(False, 0.20, metrics,
                           "伪造 token 返回的内容与合法身份差异过大（%.3f），不是同一身份" % sim)
        return Verdict(False, 0.60, metrics,
                       "伪造 token 的响应与合法身份部分相似（%.3f），需人工确认" % sim)


class AuthzTemplateDiff(Oracle):
    """缺失授权：本该要登录/更高权限的接口，在**没有凭据**时照样返回数据。

    和 IDOR 的区别：IDOR 问"换个身份能不能读别人的对象"，这里问"根本不出示身份能不能读"。
    最容易误判的情况是应用对未登录请求返回 200 的登录页/统一壳页——所以除了和
    授权视角比相似度，还要和**拒绝模板**比：拒绝模板不是硬编码的登录页，
    而是本次任务里真实取到的一次 401/403（`control` 证据），或者同主机历史里的拒绝响应。

    判定顺序：先看 probe 是否被拒 → 再看是否长得像拒绝模板 → 最后才看是否等价于数据。
    """

    name = "authz_template_diff"
    min_level = "L1"

    @dataclass
    class Args:
        min_similarity_data: float = 0.90   # 与授权视角的响应等价 → 无凭据也读到了数据
        min_similarity_deny: float = 0.85   # 与拒绝模板等价 → 只是拿到了登录页/403 页
        partial_similarity: float = 0.60    # 中间地带：交人工
        success_status: Tuple[int, ...] = (200,)
        deny_status: Tuple[int, ...] = (401, 403)
        require_deny_template: bool = False  # 没有拒绝模板时是否降级为 hypothesis

    def run(self, obs, args):
        probe = _by_role(obs, "probe")
        if not probe:
            return Verdict(False, 0.0, {}, "缺少 probe 证据", ("probe",))
        p = probe[0]
        anon = str(p.identity or "") in ("", "none")
        who = "无凭据请求" if anon else "身份 %s 的请求" % p.identity
        metrics: Dict[str, Any] = {"probe_status": p.status, "probe_identity": p.identity,
                                   "probe_anonymous": anon}

        if p.status in args.deny_status:
            return Verdict(False, 0.0, metrics, "%s被拒（%d），接口要认证" % (who, p.status))
        if p.status not in args.success_status:
            if 300 <= p.status < 400:
                return Verdict(False, 0.0, metrics,
                               "%s被重定向（%d），通常是跳登录页" % (who, p.status))
            return Verdict(False, 0.0, metrics, "%s未取得内容（%d）" % (who, p.status))

        base = _by_role(obs, "baseline")
        if not base:
            return Verdict(False, 0.55, metrics,
                           "%s返回 %d，但缺少授权视角对照，只能算 hypothesis" % (who, p.status),
                           ("baseline",))
        b = base[0]
        metrics["baseline_status"] = b.status
        metrics["baseline_identity"] = b.identity
        if b.identity == p.identity:
            return Verdict(False, 0.0, metrics, "两个观察来自同一身份，无法证明缺失授权")
        if b.status not in args.success_status:
            return Verdict(False, 0.0, metrics, "授权视角本身不成立（%d），缺少对照" % b.status)

        sim_data = 0.6 * _jaccard(b.body, p.body) + 0.4 * _len_ratio(b.body, p.body)
        metrics["similarity_data"] = round(sim_data, 4)

        deny_obs = [o for o in obs
                    if o.role == "control" or
                    (o.status in args.deny_status and o.role not in ("probe", "baseline"))]
        sim_deny = None
        if deny_obs:
            sim_deny = max(0.6 * _jaccard(d.body, p.body) + 0.4 * _len_ratio(d.body, p.body)
                           for d in deny_obs)
            metrics["similarity_deny"] = round(sim_deny, 4)
            metrics["deny_template"] = True
        else:
            metrics["deny_template"] = False

        if sim_deny is not None and sim_deny >= args.min_similarity_deny:
            return Verdict(False, 0.10, metrics,
                           "%s返回的是拒绝模板（相似度 %.3f），不是数据" % (who, sim_deny))

        # 两个不同身份拿到字节完全一样的内容：可能是越权，也可能这条接口本来就是全局
        # 共享资源（标签/枚举/配置/lesson 列表）。判定仍然成立，但必须把这句话说出来，
        # 否则用户会把"大家都能读的公开数据"当成洞去报。
        same_bytes = (b.body_sha256 == p.body_sha256) if b.body_sha256 and p.body_sha256 else False
        caveat = ""
        if same_bytes and not anon:
            metrics["identical_bytes_across_identities"] = True
            caveat = ("；两个身份拿到的是同一份字节，如果这是全局共享资源"
                      "（标签/枚举/配置这类人人可读的数据）就不算缺失授权，"
                      "先确认它的内容会不会随身份变化")

        if sim_data >= args.min_similarity_data:
            if args.require_deny_template and sim_deny is None:
                return Verdict(False, 0.60, metrics,
                               "内容与授权视角等价（%.3f），但没有拒绝模板可对照" % sim_data,
                               ("control",))
            conf = 0.92 if sim_deny is not None else 0.88
            return Verdict(True, conf, metrics,
                           "%s拿到与授权视角等价的数据（相似度 %.3f%s）%s" % (
                               who, sim_data,
                               "，且不等于拒绝模板" if sim_deny is not None else "", caveat))
        if sim_data >= args.partial_similarity:
            return Verdict(False, 0.60, metrics,
                           "%s响应与授权视角部分相似（%.3f），需人工确认" % (who, sim_data))
        return Verdict(False, 0.15, metrics,
                       "%s响应与授权视角差异过大（%.3f），不是同一份数据" % (who, sim_data))


class DomMarkerPresent(Oracle):
    """反射型 XSS：脚本**真的执行了**，而不是只被反射进 HTML。

    只接受浏览器 DOM 快照证据（`X-Pta-Capture: dom-snapshot`）。判定依赖两条
    只有"执行"才会出现的痕迹：
      1. `X-Pta-Window-Name` == nonce（脚本写 window.name）
      2. `<body ... data-pta-xss="nonce">`（脚本给 body 加属性）
    光在 HTML 里搜到载荷字符串不算——那是反射，不是执行，这正是本 oracle 要拦的误报。
    """

    name = "dom_marker_present"
    min_level = "L1"

    @dataclass
    class Args:
        require_window_name: bool = False   # 要求必须有 window.name 证据
        min_confidence: float = 0.85

    def run(self, obs, args):
        probe = _by_role(obs, "probe")
        if not probe:
            return Verdict(False, 0.0, {}, "缺少 probe 证据", ("probe",))
        o = probe[0]
        capture = (o.headers.get("x-pta-capture") or "").strip().lower()
        metrics = {"status": o.status, "capture": capture}
        if capture != "dom-snapshot":
            return Verdict(False, 0.0, metrics,
                           "证据不是浏览器 DOM 快照，无法证明脚本执行",
                           ("probe:dom_snapshot",))

        nonce = (o.headers.get("x-pta-nonce") or "").strip()
        if not nonce:
            return Verdict(False, 0.0, metrics, "证据缺少 X-Pta-Nonce，无法归因", ("probe:nonce",))

        window_name = (o.headers.get("x-pta-window-name") or "").strip()
        body_attr = _body_marker(o.text, nonce)
        reflected = nonce in o.text
        encoded = reflected and ("&lt;" in o.text or "&#" in o.text) and "<img" not in o.text
        metrics.update({
            "nonce": nonce,
            "window_name_match": window_name == nonce,
            "body_attr": body_attr,
            "reflected_only": reflected and not (window_name == nonce or body_attr),
            "encoded": encoded,
        })

        if window_name == nonce and body_attr:
            conf = 0.95
        elif window_name == nonce:
            conf = 0.92
        elif body_attr:
            conf = 0.88
        else:
            if encoded:
                rationale = "载荷被 HTML 实体编码后输出，未执行"
            elif reflected:
                rationale = "载荷只被反射进 HTML，没有执行痕迹"
            else:
                rationale = "响应里既没有执行痕迹也没有反射载荷"
            if args.require_window_name:
                rationale += "（要求 window.name 证据）"
            return Verdict(False, 0.15 if reflected else 0.0, metrics, rationale)

        if args.require_window_name and window_name != nonce:
            return Verdict(False, 0.60, metrics, "要求 window.name 证据，但未观察到",
                           ("probe:window_name",))
        conf = min(conf, 0.95)
        return Verdict(conf >= args.min_confidence, conf, metrics,
                       "脚本已执行：%s" % ("window.name + body 属性" if body_attr and window_name == nonce
                                         else "window.name" if window_name == nonce else "body 属性"))


def _body_marker(html: str, nonce: str) -> bool:
    """脚本执行后给 <body> 打的属性；只在 body 起始标签内找，避免属性值文本误命中。"""
    n = re.escape(nonce)
    for m in re.finditer(r"<body\b[^>]*>", html, re.I):
        tag = m.group(0)
        if re.search(r"data-pta-xss\s*=\s*[\"']?%s" % n, tag, re.I):
            return True
    return False


# ---------- 批量赋值：把"权限"从字符串变成可比较的等级 ----------
_PRIV_ROLE_VALUES = {
    "guest": 0, "anonymous": 0, "visitor": 0,
    "user": 1, "member": 1, "customer": 1, "employee": 1, "viewer": 1,
    "moderator": 2, "mod": 2, "staff": 2, "manager": 2, "editor": 2, "operator": 2,
    "admin": 3, "administrator": 3, "sysadmin": 3,
    "superuser": 4, "superadmin": 4, "root": 4, "owner": 4,
}

_FLAG_VALUES = {"false": 0, "true": 3, "0": 0, "1": 3, "no": 0, "yes": 3, "": 0}

# 字段名 → 值排名表。只有这些字段名参与比较，避免把普通业务数字当权限。
PRIVILEGE_FIELDS: Dict[str, Dict[str, int]] = {
    "role": _PRIV_ROLE_VALUES,
    "user_role": _PRIV_ROLE_VALUES,
    "role_name": _PRIV_ROLE_VALUES,
    "account_type": _PRIV_ROLE_VALUES,
    "user_type": _PRIV_ROLE_VALUES,
    "is_admin": dict(_FLAG_VALUES, **{"true": 3}),
    "is_superuser": {"false": 0, "true": 4, "0": 0, "1": 4},
    "is_staff": {"false": 0, "true": 2, "0": 0, "1": 2},
    "admin": dict(_FLAG_VALUES, **{"true": 3}),
    "staff": {"false": 0, "true": 2, "0": 0, "1": 2},
    "privilege": {"none": 0, "user": 1, "admin": 3, "root": 4},
}

# 纯数字型权限字段：值本身就是等级
NUMERIC_PRIVILEGE_FIELDS = frozenset({
    "privilege_level", "access_level", "permission_level", "clearance", "level",
})


def _rank_of(key: str, value: Any, fields: Dict[str, Dict[str, int]]) -> Optional[int]:
    name = str(key).strip().lower().replace("-", "_")
    mapping = fields.get(name)
    if mapping is not None:
        if isinstance(value, bool):
            token = "true" if value else "false"
        else:
            token = str(value).strip().lower()
        return mapping.get(token)
    if name in NUMERIC_PRIVILEGE_FIELDS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def _privileges(data: Any, fields: Dict[str, Dict[str, int]],
                prefix: str = "") -> Dict[str, Dict[str, Any]]:
    """从 JSON 响应里收集权限字段：{路径: {value, rank}}。只读，不改任何东西。"""
    found: Dict[str, Dict[str, Any]] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            path = "%s.%s" % (prefix, key) if prefix else str(key)
            rank = _rank_of(key, value, fields)
            if rank is not None:
                found[path] = {"value": value, "rank": rank}
            if isinstance(value, (dict, list)):
                found.update(_privileges(value, fields, path))
    elif isinstance(data, list):
        for i, item in enumerate(data[:20]):
            if isinstance(item, (dict, list)):
                found.update(_privileges(item, fields, "%s[%d]" % (prefix, i)))
    return found


def _text(body: bytes) -> str:
    """响应体转文本：指纹匹配只需要"这个词出现过没有"，编码坏了也不该中断判定。"""
    return body.decode("utf-8", "replace") if body else ""


def _load_json(body: bytes) -> Optional[Any]:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None


def _max_rank(found: Dict[str, Dict[str, Any]]) -> Optional[int]:
    ranks = [v["rank"] for v in found.values() if v.get("rank") is not None]
    return max(ranks) if ranks else None


class FieldEscalationEffect(Oracle):
    """批量赋值：同一个身份往请求体里多塞权限字段，响应里的权限等级被抬高了。

    纯 HTTP 可判，只有一个硬条件：**相对 baseline 必须真的涨级**（require_privilege_delta）。
    字段被接受但没有涨级（响应与 baseline 等权），只能算"字段被忽略"，不是漏洞。
    """

    name = "field_escalation_effect"
    min_level = "L2"

    @dataclass
    class Args:
        min_delta: int = 1
        success_status: Tuple[int, ...] = (200,)
        require_privilege_delta: bool = True
        fields: Optional[Dict[str, Dict[str, int]]] = None

    def run(self, obs: Sequence[Observation], args: "FieldEscalationEffect.Args") -> Verdict:
        fields = args.fields or PRIVILEGE_FIELDS
        probes = _by_role(obs, "probe")
        baselines = _by_role(obs, "baseline")
        if not probes:
            return Verdict(False, 0.0, {}, "缺少 probe 证据", ("probe",))
        p = probes[-1]
        if p.status in (401, 403):
            return Verdict(False, 0.0, {"probe_status": p.status},
                           "服务端拒绝了这次写入（%d）" % p.status)
        if p.status in (400, 422):
            return Verdict(False, 0.0, {"probe_status": p.status},
                           "权限字段被服务端校验拒绝（%d）" % p.status)
        if p.status not in args.success_status:
            return Verdict(False, 0.0, {"probe_status": p.status},
                           "写入未成功（%d），无从判断是否越权" % p.status)
        if not baselines:
            return Verdict(False, 0.55, {"probe_status": p.status},
                           "缺少 baseline 证据，无法比较权限等级", ("baseline",))
        b = baselines[-1]
        if b.status not in args.success_status:
            return Verdict(False, 0.0, {"probe_status": p.status, "baseline_status": b.status},
                           "baseline 本身不成功（%d），说明提交的合法载荷不对" % b.status)

        p_found = _privileges(_load_json(p.body), fields)
        b_found = _privileges(_load_json(b.body), fields)
        p_rank, b_rank = _max_rank(p_found), _max_rank(b_found)
        delta = (p_rank - b_rank) if (p_rank is not None and b_rank is not None) else None
        metrics: Dict[str, Any] = {
            "probe_status": p.status, "baseline_status": b.status,
            "probe_rank": p_rank, "baseline_rank": b_rank, "delta": delta,
            "probe_fields": p_found, "baseline_fields": b_found,
            "identity": p.identity,
        }

        if p_rank is None:
            if b_rank is None:
                return Verdict(False, 0.15, metrics,
                               "两边响应里都没有可量化的权限字段，无法判定")
            return Verdict(False, 0.15, metrics,
                           "probe 响应里没有权限字段：附加字段很可能被服务端丢弃",
                           ("probe:privilege_field",))

        if delta is None:                       # baseline 里没有权限字段，按最低等级 0 算
            delta = p_rank
            metrics["delta"] = delta

        if delta < args.min_delta:
            detail = "baseline %s → probe %s" % (
                b_rank if b_rank is not None else "（无权限字段）", p_rank)
            if args.require_privilege_delta and delta <= 0:
                return Verdict(False, 0.20, metrics,
                               "响应里的权限等级没有提升（%s），字段被接受但未越权" % detail)
            return Verdict(False, 0.55, metrics,
                           "出现权限字段但没有可确认的提升（%s）" % detail,
                           ("probe:privilege_delta",))

        return Verdict(True, 0.90, metrics,
                       "批量赋值生效：附加字段把响应权限等级抬高了 %d 级（%s → %s）"
                       % (delta, b_rank if b_rank is not None else "无", p_rank))


# ---------------------------------------------------------------- 写入生效

def _flatten(data: Any, prefix: str = "") -> Dict[str, Any]:
    """把 JSON 摊平成 `a.b[0].c -> 值`，只用于"回读到底变了哪个字段"。"""
    out: Dict[str, Any] = {}
    if isinstance(data, dict):
        for k, v in list(data.items())[:200]:
            key = "%s.%s" % (prefix, k) if prefix else str(k)
            out.update(_flatten(v, key))
    elif isinstance(data, list):
        for i, v in enumerate(data[:50]):
            out.update(_flatten(v, "%s[%d]" % (prefix, i)))
    else:
        out[prefix] = data
    return out


class WriteEffectVisible(Oracle):
    """写入型越权（IDOR write）：A 改 B 的对象，B 回读时看到了 A 写进去的标记。

    为什么必须三段证据：
    - 只有 baseline（B 读）：对象长什么样；
    - 只有 probe（A 写，200/204）：只能说明"服务端接受了这次请求"，接受 ≠ 落到别人对象上；
    - 只有 verify（B 再读）：只能说明"对象变了"，变了可能是别人改的、或时间字段在动。
    三段合起来，且变化里出现本次注入的唯一标记，才算写入越权。

    另外两条硬条件：
    1. 写入身份必须与属主身份不同，否则是"自写自读"，不构成越权（直接否）；
    2. 回读变化要少：整页都在变（时间戳、推荐位）时标记不可归因，只能算 0.55。
    """

    name = "write_effect_visible"
    min_level = "L2"

    @dataclass
    class Args:
        success_status: Tuple[int, ...] = (200, 201, 204)
        verify_status: Tuple[int, ...] = (200,)
        marker_pattern: str = r"^pta[0-9a-z]{8}$"
        max_changed: int = 4

    def run(self, obs: Sequence[Observation], args: "WriteEffectVisible.Args") -> Verdict:
        probes = _by_role(obs, "probe")
        baselines = _by_role(obs, "baseline")
        verifies = _by_role(obs, "verify")
        if not probes:
            return Verdict(False, 0.0, {}, "缺少 probe 证据（写入请求）", ("probe",))
        p = probes[-1]
        if not baselines:
            return Verdict(False, 0.0, {"probe_status": p.status},
                           "缺少 baseline 证据（属主读到的原样）", ("baseline",))
        b = baselines[-1]
        if not verifies:
            return Verdict(False, 0.0, {"probe_status": p.status},
                           "写完没有回读：写入被接受不等于改到了对方对象",
                           ("verify",))
        v = verifies[-1]
        metrics: Dict[str, Any] = {
            "probe_status": p.status, "baseline_status": b.status, "verify_status": v.status,
            "probe_method": p.method, "probe_identity": p.identity,
            "baseline_identity": b.identity, "verify_identity": v.identity,
        }

        if p.status in (401, 403):
            return Verdict(False, 0.0, metrics, "写入被服务端拒绝（%d）" % p.status)
        if p.status not in args.success_status:
            return Verdict(False, 0.0, metrics,
                           "写入没有被接受（%d），没有越权可谈" % p.status)
        if p.identity == b.identity:
            return Verdict(False, 0.20, metrics,
                           "写入身份与属主身份相同（%s），这是自写自读，不构成越权" % p.identity)
        if v.status in (401, 403):
            return Verdict(False, 0.15, metrics, "回读被拒绝（%d），无法确认写入落到对象上" % v.status)
        if v.status not in args.verify_status:
            return Verdict(False, 0.15, metrics, "回读没有正常响应（%d）" % v.status)

        bj, vj = _load_json(b.body), _load_json(v.body)
        if bj is None or vj is None:
            return Verdict(False, 0.15, metrics,
                           "基线或回读不是 JSON，无法逐字段比较写入是否生效")
        bf, vf = _flatten(bj), _flatten(vj)
        pat = re.compile(args.marker_pattern)
        if any(isinstance(x, str) and pat.match(x) for x in bf.values()):
            return Verdict(False, 0.10, metrics,
                           "基线里已经存在同类标记，本次写入无法归因")
        changed = {k: vf[k] for k in vf if k not in bf or bf[k] != vf[k]}
        markers = [k for k, val in changed.items() if isinstance(val, str) and pat.match(val)]
        metrics.update({
            "changed_keys": sorted(changed)[:args.max_changed],
            "changed_count": len(changed),
            "marker_keys": markers,
            "similarity": round(_sim(b.body, v.body), 4),
        })

        if not changed:
            return Verdict(False, 0.15, metrics,
                           "回读与基线完全一致：写入没有落到这个对象上")
        if not markers:
            return Verdict(False, 0.15, metrics,
                           "回读变了（%d 个字段）但没有本次写入的标记，变化不可归因"
                           % len(changed))
        if len(changed) > args.max_changed:
            return Verdict(False, 0.55, metrics,
                           "回读变化过多（%d 个字段），标记不可归因" % len(changed),
                           ("verify:too_many_changes",))
        conf = 0.95 if len(changed) <= 2 else 0.92
        return Verdict(True, conf, metrics,
                       "写入越权成立：%s 身份写入后，属主回读到了本次标记（%s）"
                       % (p.identity, ", ".join(markers[:3])))


# ---------------------------------------------------------------- 时间分布

def _median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _mad(xs: Sequence[float]) -> float:
    """绝对离散度（毫秒）：MAD。

    单独看相对离散度会被"中位数很小"放大：内网响应 1.7ms 时，0.9ms 的正常抖动
    就是 0.53 的 CV，会把每一轮都判成"抖动过大"。所以噪声判据同时给一个绝对下限。
    """
    if not xs:
        return 0.0
    m = _median(xs)
    return _median([abs(x - m) for x in xs])


def _cv(xs: Sequence[float]) -> float:
    """相对离散度：MAD / 中位数。

    不用标准差：一次 GC 或调度抖动就能把 stddev 拉爆，而中位数攻击真正怕的是
    "整体漂移"，不是"偶尔一个尖刺"。绝对尖刺由 spread（max-min 对比 effect）兜底。
    """
    if not xs:
        return 0.0
    m = _median(xs)
    if m <= 0:
        return 0.0
    return _mad(xs) / m


def _spread(xs: Sequence[float]) -> float:
    return (max(xs) - min(xs)) if xs else 0.0


def _bootstrap_p(baseline: Sequence[float], probe: Sequence[float],
                 n_boot: int, rng: Any) -> float:
    """单侧 bootstrap：H0 = 注入组不比基线慢。返回 P(median(probe)-median(base) <= 0)。"""
    nb, npb = len(baseline), len(probe)
    hits = 0
    for _ in range(n_boot):
        b = [baseline[rng.randrange(nb)] for _ in range(nb)]
        p = [probe[rng.randrange(npb)] for _ in range(npb)]
        if _median(p) - _median(b) <= 0.0:
            hits += 1
    return (hits + 1.0) / (n_boot + 1.0)


class TimingDistributionShift(Oracle):
    """时间盲注：注入组的中位耗时显著高于基线，且两组采样都足够稳。

    为什么不是比平均耗时：网络抖动是长尾的，均值被单次尖刺带偏；
    中位数 + 单侧 bootstrap 只回答一个问题——如果注入没生效，
    看到这么大差距的概率有多大。
    """

    name = "timing_distribution_shift"
    min_level = "L2"

    @dataclass(frozen=True)
    class Args:
        min_samples: int = 5
        cv_max: float = 0.15
        abs_noise_ms: float = 5.0
        min_effect_ms: float = 1800.0
        alpha: float = 0.01
        n_boot: int = 10000
        success_status: Tuple[int, ...] = (200,)

    def run(self, obs: Sequence[Observation], args: "TimingDistributionShift.Args") -> Verdict:
        base = _by_role(obs, "baseline")
        probe = _by_role(obs, "probe")
        if not probe:
            return Verdict(False, 0.0, {}, "缺少注入请求，无法判断延时", ("probe",))
        if not base:
            return Verdict(False, 0.0, {}, "缺少基线请求，无法判断延时是否由注入造成", ("baseline",))

        b, p = base[0], probe[0]
        if p.status in (401, 403):
            return Verdict(False, 0.0, {"probe_status": p.status},
                           "注入请求被拒绝（%d），延时不是注入造成的" % p.status)
        if p.status >= 400:
            return Verdict(False, 0.0, {"probe_status": p.status},
                           "注入请求返回 %d，没有可比较的正常响应" % p.status)

        zeros_b = sum(1 for t in b.timings if not t or t <= 0)
        zeros_p = sum(1 for t in p.timings if not t or t <= 0)
        b_ms = [float(t) for t in b.timings if t and t > 0]
        p_ms = [float(t) for t in p.timings if t and t > 0]
        # 第一次请求带连接建立/冷启动开销（甚至 DNS、TLS 握手），不参与统计。
        # 只在样本数超过下限时才丢，保证结论至少建立在 min_samples 个点上。
        dropped = 0
        if len(b_ms) > args.min_samples:
            b_ms = b_ms[1:]
            dropped += 1
        if len(p_ms) > args.min_samples:
            p_ms = p_ms[1:]
            dropped += 1
        metrics = {
            "baseline_samples": len(b_ms),
            "probe_samples": len(p_ms),
            "warmup_dropped": dropped,
            "zero_baseline": zeros_b,
            "zero_probe": zeros_p,
            "baseline_median_ms": round(_median(b_ms), 3) if b_ms else 0.0,
            "probe_median_ms": round(_median(p_ms), 3) if p_ms else 0.0,
        }

        if len(b_ms) < args.min_samples or len(p_ms) < args.min_samples:
            missing = []
            if len(b_ms) < args.min_samples:
                missing.append("baseline:timings")
            if len(p_ms) < args.min_samples:
                missing.append("probe:timings")
            # 0.0ms 不是"很快"，是"这个时钟量不出来"。混在一起只会让人以为样本不够。
            if zeros_b or zeros_p:
                return Verdict(False, 0.0, metrics,
                               "采样里出现 %d 个 0ms（基线 %d / 注入 %d）：时钟精度不足，这些点不可用"
                               % (zeros_b + zeros_p, zeros_b, zeros_p), tuple(missing))
            return Verdict(False, 0.0, metrics,
                           "采样不足（基线 %d / 注入 %d，至少各 %d 次）"
                           % (len(b_ms), len(p_ms), args.min_samples), tuple(missing))

        cv_b, cv_p = _cv(b_ms), _cv(p_ms)
        mad_b, mad_p = _mad(b_ms), _mad(p_ms)
        metrics.update({"cv_baseline": round(cv_b, 4), "cv_probe": round(cv_p, 4),
                        "mad_baseline_ms": round(mad_b, 3),
                        "mad_probe_ms": round(mad_p, 3),
                        "spread_baseline_ms": round(_spread(b_ms), 3),
                        "spread_probe_ms": round(_spread(p_ms), 3)})
        # 噪声判据要看"相对于要判的差值"：差 2000ms 时抖 6ms 根本不影响结论。
        # 所以在算出 effect 之后再判，允许的抖动 = max(绝对下限, effect/20)。
        effect = _median(p_ms) - _median(b_ms)
        metrics["effect_ms"] = round(effect, 3)
        noise_allowance = max(args.abs_noise_ms, max(effect, 0.0) / 20.0)
        metrics["noise_allowance_ms"] = round(noise_allowance, 3)
        noisy = ((cv_b > args.cv_max and mad_b > noise_allowance) or
                 (cv_p > args.cv_max and mad_p > noise_allowance) or
                 # 相对离散度离谱（>4 倍阈值）时，无论差值多大都不能归因：
                 # 一组 10/400/30/900/60 的基线里，中位数本身就没有意义。
                 cv_b > 4.0 * args.cv_max or cv_p > 4.0 * args.cv_max)
        if noisy:
            return Verdict(False, 0.15, metrics,
                           "采样抖动过大（相对离散度 %.3f / %.3f > %.2f，绝对 %.1f / %.1f ms > 允许 %.1f ms），这一轮不可信，需要重测"
                           % (cv_b, cv_p, args.cv_max, mad_b, mad_p, noise_allowance))

        if effect < args.min_effect_ms:
            return Verdict(False, 0.15, metrics,
                           "延时差 %.0fms 低于阈值 %.0fms，不能归因于注入"
                           % (effect, args.min_effect_ms))

        # 单次尖刺不能超过差值的一半，否则"慢"可能只是某一次卡住
        if _spread(b_ms) >= effect / 2.0 or _spread(p_ms) >= effect / 2.0:
            return Verdict(False, 0.15, metrics,
                           "单次采样跨度接近差值（基线 %.0fms / 注入 %.0fms，差值 %.0fms），不能归因"
                           % (_spread(b_ms), _spread(p_ms), effect))

        try:
            seed = int(p.body_sha256[:16], 16)
        except (ValueError, TypeError):
            seed = 0
        p_value = _bootstrap_p(b_ms, p_ms, args.n_boot, random.Random(seed))
        metrics.update({"p_value": round(p_value, 6), "n_boot": args.n_boot, "seed": seed})
        if p_value > args.alpha:
            return Verdict(False, 0.25, metrics,
                           "延时差 %.0fms 但统计上不显著（p=%.4f > %.2f）"
                           % (effect, p_value, args.alpha))

        conf = 0.94 if effect >= 1.5 * args.min_effect_ms and p_value <= args.alpha / 10.0 else 0.90
        return Verdict(True, conf, metrics,
                       "时间盲注生效：注入组中位延时比基线高 %.0fms（%.0f → %.0f ms，p=%.4f）"
                       % (effect, _median(b_ms), _median(p_ms), p_value))


INTERNAL_SIGNATURES: Dict[str, Tuple[str, ...]] = {
    # 每一组都是"这个服务独有、普通页面几乎不会同时出现的词"，靠它区分"打到了内网服务"
    # 和"应用把自己的页面回显了一遍"。
    "aws_metadata": ("ami-id", "instance-id", "security-credentials", "placement/", "public-keys/"),
    "gcp_metadata": ("instance/service-accounts", "project/project-id", "computeMetadata"),
    "azure_metadata": ("instance/compute", "metadata/instance", "azEnvironment"),
    "docker_api": ("ApiVersion", "MinAPIVersion", "GitCommit"),
    "k8s_apiserver": ("gitVersion", "gitCommit", "platform"),
    "elasticsearch": ("cluster_name", "lucene_version", "You Know, for Search"),
    "etcd": ("etcdserver", "etcdcluster"),
}


class InternalServiceFingerprint(Oracle):
    """SSRF 打进内网：靠回显里的服务指纹判定，而不是靠回连。

    为什么不能等回调：元数据服务、Docker API、etcd 这类内网目标不会主动连我们，
    但它们会用自己的格式回一句话。回显里出现两个以上该服务独有的特征串，
    就说明请求确实由目标发到了那个地址——这是不依赖外网出口的唯一证据。

    为什么必须比基线：很多应用会把自己的聚合页原样返回（参数根本没被当成 URL），
    页里本来就写着 "cluster_name" 之类的词。基线里已有同一组特征，直接判否。

    为什么单特征只给 0.55：一个 "platform" 之类的通用词撞上概率不低，
    没有第二个特征佐证时只算 hypothesis。
    """

    name = "internal_service_fingerprint"
    min_level = "L2"

    @dataclass
    class Args:
        signatures: Optional[Dict[str, Tuple[str, ...]]] = None
        min_markers: int = 2
        success_status: Tuple[int, ...] = (200,)
        require_baseline_clean: bool = True

    @staticmethod
    def _table() -> Dict[str, Tuple[str, ...]]:
        return INTERNAL_SIGNATURES

    def run(self, obs: Sequence[Observation],
            args: "InternalServiceFingerprint.Args") -> Verdict:
        probes = _by_role(obs, "probe")
        baselines = _by_role(obs, "baseline")
        if not probes:
            return Verdict(False, 0.0, {}, "缺少 probe 证据（带内网地址的请求）", ("probe",))
        p = probes[-1]
        metrics: Dict[str, Any] = {"probe_status": p.status, "probe_len": p.body_len}
        if p.status in (401, 403):
            return Verdict(False, 0.0, metrics, "注入请求被服务端拒绝（%d）" % p.status)
        if p.status not in args.success_status:
            return Verdict(False, 0.05, metrics,
                           "注入请求没有正常响应（%d），拿不到回显" % p.status)

        table = args.signatures or self._table()
        text = _text(p.body)
        name, hits = "", []
        for cand, group in table.items():
            found = [m for m in group if m in text]
            if len(found) > len(hits):
                name, hits = cand, found
        metrics.update({"service": name, "markers_found": hits,
                        "markers_count": len(hits)})

        if not baselines:
            return Verdict(False, 0.0, metrics, "缺少 baseline 证据（不带载荷的同一请求）",
                           ("baseline",))
        b = baselines[-1]
        btext = _text(b.body)
        base_hits = [m for m in table.get(name, ()) if m in btext] if name else []
        metrics["baseline_markers"] = base_hits
        # 回显与基线逐字相同：参数根本没进 URL，或者应用把响应重写了
        if p.body and b.body and p.body == b.body:
            return Verdict(False, 0.15, metrics,
                           "回显与基线逐字相同，参数没有改变请求目标")
        if not hits:
            return Verdict(False, 0.10, metrics,
                           "回显里没有任何内网服务特征：参数可能不在控制 URL，或响应被重写",
                           ("probe:service_markers",))
        if args.require_baseline_clean and base_hits:
            return Verdict(False, 0.15, metrics,
                           "基线本来就能看到 %s 的 %d 个特征，参数不在控制请求目标"
                           % (name, len(base_hits)))
        if len(hits) < args.min_markers:
            return Verdict(False, 0.55, metrics,
                           "只命中 %s 的 1 个特征（%s），可能是通用词巧合"
                           % (name, hits[0]), ("probe:more_markers",))
        conf = 0.95 if len(hits) >= 3 else 0.90
        return Verdict(True, conf, metrics,
                       "参数把请求打到了内网服务 %s（命中 %d 个特征：%s）"
                       % (name, len(hits), "、".join(hits[:4])))


class UploadReadback(Oracle):
    """文件上传：上传被接受 + 回读拿回本次标记 = 未授权文件落地。

    为什么不能只凭上传返回 200：多目标会把文件改名、存到对象存储、或只登记不上盘。
    真正要证明的是"我们写的字节能被匿名取回"，所以回读必须由独立请求完成。

    分级：
    - 回读被当 html/php/js 返回（0.95）：浏览器或解释器会处理它，这是最坏情况；
    - 回读是纯文本/二进制下载（0.88）：文件确实落地并可未授权取回，但未必执行。
    报告里这两档必须分开写，不能都说"上传 RCE"。
    """

    name = "upload_readback"
    min_level = "L2"

    @dataclass
    class Args:
        success_status: Tuple[int, ...] = (200, 201, 204)
        verify_status: Tuple[int, ...] = (200,)
        marker_pattern: str = r"pta[0-9a-z]{8}"
        executable_types: Tuple[str, ...] = ("text/html", "application/xhtml",
                                             "php", "javascript", "text/x-")

    def run(self, obs: Sequence[Observation], args: "UploadReadback.Args") -> Verdict:
        probes = _by_role(obs, "probe")
        verifies = _by_role(obs, "verify")
        if not probes:
            return Verdict(False, 0.0, {}, "缺少 probe 证据（上传请求）", ("probe",))
        p = probes[-1]
        metrics: Dict[str, Any] = {"probe_status": p.status, "probe_identity": p.identity}
        if not verifies:
            return Verdict(False, 0.0, metrics,
                           "上传后没有回读：文件被接受不等于能被取回", ("verify",))
        v = verifies[-1]
        metrics.update({"verify_status": v.status, "verify_identity": v.identity,
                        "verify_content_type": v.content_type,
                        "verify_url": v.url})
        if p.status in (401, 403):
            return Verdict(False, 0.0, metrics, "上传被服务端拒绝（%d）" % p.status)
        if p.status not in args.success_status:
            return Verdict(False, 0.0, metrics,
                           "上传没有被接受（%d），谈不上文件落地" % p.status)
        if v.status in (401, 403):
            return Verdict(False, 0.10, metrics, "回读被拒绝（%d）" % v.status)
        if v.status not in args.verify_status:
            return Verdict(False, 0.15, metrics,
                           "回读没有正常响应（%d）：文件可能存到了别处" % v.status)

        pat = re.compile(args.marker_pattern)
        hit = pat.search(v.text)
        metrics["marker_in_verify"] = bool(hit)
        metrics["marker_in_probe_echo"] = bool(pat.search(p.text))
        if not hit:
            echo = "（上传响应里出现了标记，但回读没有：回显≠落地）" \
                if metrics["marker_in_probe_echo"] else ""
            return Verdict(False, 0.15, metrics,
                           "回读拿到了内容，但没有本次写入的标记%s" % echo)

        ctype = (v.content_type or "").lower()
        executable = any(t in ctype for t in args.executable_types)
        if executable:
            return Verdict(True, 0.95, metrics,
                           "上传的文件被当可执行类型返回（%s）：匿名可回读，且浏览器/解释器会处理它"
                           % (ctype.split(";")[0] or "unknown"))
        return Verdict(True, 0.88, metrics,
                       "上传的文件可被匿名回读（%s），但返回类型不可执行："
                       "落地成立，「RCE」不成立" % (ctype.split(";")[0] or "unknown"))


class DeserializationMarkerPresent(Oracle):
    """反序列化：把序列化流塞进请求体，服务端解析到我们的类名后报错。

    这是"入口存在"的证据，不是"可利用"的证据：
    - 命中 ClassNotFoundException / InvalidClassException → 载荷确实进了 ObjectInputStream；
    - 但它只说明解析到了类名，没说明存在能拼出利用链的 gadget。
    所以最高 0.80，报告里必须写成「反序列化入口存在」，不能写「反序列化 RCE」。
    """

    name = "deserialization_marker_present"
    min_level = "L1"

    @dataclass
    class Args:
        markers: Tuple[str, ...] = (
            "java.io.InvalidClassException",
            "java.lang.ClassNotFoundException",
            "Cannot deserialize",
            "unrecognized token",
            "failed to deserialize",
            "pickle.UnpicklingError",
            "__PHP_Incomplete_Class",
            "SerializationException",
        )
        baseline_status: Tuple[int, ...] = (200, 400, 415, 422, 500)

    def run(self, obs: Sequence[Observation], args: "DeserializationMarkerPresent.Args") -> Verdict:
        probes = _by_role(obs, "probe")
        baselines = _by_role(obs, "baseline")
        if not probes:
            return Verdict(False, 0.0, {}, "缺少 probe 证据（序列化请求体）", ("probe",))
        p = probes[-1]
        metrics: Dict[str, Any] = {"probe_status": p.status,
                                   "probe_content_type": p.content_type}
        if p.status in (401, 403):
            return Verdict(False, 0.0, metrics, "请求被拒绝（%d），载荷没进业务逻辑" % p.status)

        ptext = p.text
        hits = [m for m in args.markers if m.lower() in ptext.lower()]
        metrics["markers"] = hits
        if not hits:
            return Verdict(False, 0.10, metrics,
                           "响应里没有反序列化相关异常：载荷可能被当普通 body 丢掉")

        btext = ""
        if baselines:
            b = baselines[-1]
            btext = b.text
            metrics["baseline_status"] = b.status
            # 基线相同请求（不带序列化流）本来就报同样的错，说明错误来自框架默认处理，
            # 不是"解析了我们的字节"
            same = [m for m in hits if m.lower() in btext.lower()]
            metrics["markers_in_baseline"] = same
            if len(same) == len(hits):
                return Verdict(False, 0.15, metrics,
                               "基线也报同样的异常（%s），错误不可归因于序列化流"
                               % ", ".join(same[:2]))
        return Verdict(True, 0.80, metrics,
                       "载荷进了反序列化器（命中 %s）：入口存在，但未证明有可用 gadget"
                       % "、".join(hits[:2]))


class IdempotencyViolation(Oracle):
    """竞态：同一个请求同时发 N 发，看服务端是否把同一操作接受了多次。

    判据刻意只看状态码，不看业务字段——"成功了几发"本身就有意义：
    - 幂等接口只有 1 发拿到 2xx，其余是 409/423/400（"你已经领过了"）；
    - 不幂等接口会让多发同时通过，因为两次"查你有没有领过"都发生在
      "扣掉这一次"之前。

    它证明的是**重复被接受**，不是"被扣了几次钱"——后者要读余额，
    而读余额的接口每个目标都不一样。所以最高 0.90，报告里写「同一操作被接受多次」。
    """

    name = "idempotency_violation"
    min_level = "L2"

    @dataclass
    class Args:
        burst: int = 5
        success_status: Tuple[int, ...] = (200, 201, 202, 204)
        reject_status: Tuple[int, ...] = (400, 409, 422, 423, 429)
        min_success: int = 2

    def run(self, obs: Sequence[Observation], args: "IdempotencyViolation.Args") -> Verdict:
        probes = _by_role(obs, "probe")
        if not probes:
            return Verdict(False, 0.0, {}, "缺少 probe 证据（并发突发）", ("probe",))
        p = probes[-1]
        statuses = tuple(p.burst_statuses)
        if not statuses:
            # 单发证据不是竞态证据：多发同时到达才有"重复"可言
            return Verdict(False, 0.0, {"probe_status": p.status},
                           "没有并发突发证据：单发请求无法说明重复提交会不会被接受",
                           ("probe:burst",))

        successes = [s for s in statuses if s in args.success_status]
        rejects = [s for s in statuses if s in args.reject_status]
        metrics: Dict[str, Any] = {"burst": len(statuses), "statuses": list(statuses),
                                   "successes": len(successes), "rejects": len(rejects)}
        if not successes:
            if rejects:
                return Verdict(False, 0.15, metrics,
                               "%d 发全被拒（%s）：请求本身可能无效，也可能幂等守住了"
                               % (len(statuses), ",".join(str(s) for s in sorted(set(rejects)))))
            return Verdict(False, 0.10, metrics,
                           "%d 发都没拿到 2xx（%s）：没有证据说同一操作被接受了两次"
                           % (len(statuses), ",".join(str(s) for s in sorted(set(statuses)))))
        if len(successes) < args.min_success:
            return Verdict(False, 0.15, metrics,
                           "%d 发里只有 1 发成功，其余被挡（%s）：幂等性在这里是生效的"
                           % (len(statuses), ",".join(str(s) for s in sorted(set(rejects))) or "无"))
        return Verdict(True, 0.90, metrics,
                       "同一请求并发 %d 发，有 %d 发拿到 2xx（%s）：判定与扣减之间没有原子性"
                       % (len(statuses), len(successes),
                          ",".join(str(s) for s in sorted(set(successes)))))


class CsrfTokenNotEnforced(Oracle):
    """CSRF：把令牌从请求里摘掉，改状态的请求仍然被接受。

    难点不是"发没发出去"，而是"2xx 到底证明了什么"：
    - 接口可能幂等无副作用（删一个已删的对象也返回 204）；
    - 也可能根本不要求身份（那 CSRF 无从谈起，那是缺失授权）。
    所以判据分三段，缺一段就降级，不硬凑：
      1. 带令牌的同一请求必须成功，否则这次测试不成立；
      2. 摘掉令牌后必须 2xx，否则防护生效；
      3. 有匿名对照（同 URL 无身份 → 401/403）才敢说"只差一个令牌"（0.90）；
         没有对照只能说到 0.75，并且要明说"不排除这个接口本来就公开"。
    """

    name = "csrf_token_not_enforced"
    min_level = "L2"

    @dataclass
    class Args:
        success_status: Tuple[int, ...] = (200, 201, 202, 204)
        deny_status: Tuple[int, ...] = (401, 403)
        # 200 的壳里写着"令牌无效"是最常见的一种假通过
        reject_words: Tuple[str, ...] = (
            "csrf", "invalid token", "token invalid", "token mismatch",
            "无效的令牌", "令牌无效", "校验失败", "forbidden", "not allowed", "无权限",
        )

    def run(self, obs: Sequence[Observation], args: "CsrfTokenNotEnforced.Args") -> Verdict:
        baselines = _by_role(obs, "baseline")
        probes = _by_role(obs, "probe")
        controls = _by_role(obs, "control")
        if not baselines:
            return Verdict(False, 0.0, {}, "缺少 baseline 证据（带令牌的同一请求）", ("baseline",))
        if not probes:
            return Verdict(False, 0.0, {}, "缺少 probe 证据（摘掉令牌的请求）", ("probe",))
        b = baselines[-1]
        p = probes[-1]
        metrics: Dict[str, Any] = {"baseline_status": b.status, "probe_status": p.status,
                                   "probe_method": p.method, "probe_url": p.url}
        if b.status not in args.success_status:
            return Verdict(False, 0.0, metrics,
                           "带令牌的原始请求本身没成功（%d）：这次测试不成立，"
                           "不能据此说有没有防护" % b.status)
        if p.status in args.deny_status:
            return Verdict(False, 0.0, metrics,
                           "摘掉令牌后被拒（%d）：CSRF 防护在起作用" % p.status)
        if p.status not in args.success_status:
            return Verdict(False, 0.10, metrics,
                           "摘掉令牌后返回 %d（既不是成功也不是明确拒绝）：说明不了防护状态"
                           % p.status)

        ptext = p.text.lower()
        hits = [w for w in args.reject_words if w.lower() in ptext]
        metrics["reject_words_in_probe"] = hits
        if hits:
            return Verdict(False, 0.10, metrics,
                           "摘掉令牌后是 %d 但响应体里有拒绝语义（%s）：多半是统一壳页"
                           % (p.status, "、".join(hits[:2])))

        # 匿名对照是"这是 CSRF 而不是无授权"的分界线：匿名也能改，就不是 CSRF。
        anon = [c for c in controls if str(c.identity) in ("none", "", "None")]
        if anon:
            a = anon[-1]
            metrics["anon_status"] = a.status
            if a.status in args.success_status:
                return Verdict(False, 0.20, metrics,
                               "匿名请求也能成功（%d）：这不是 CSRF，是接口没做授权"
                               % a.status)
            if a.status in args.deny_status:
                return Verdict(True, 0.90, metrics,
                               "匿名被拒（%d）、带令牌成功、摘掉令牌仍成功（%d）："
                               "服务端只校验了会话，没把令牌当放行条件"
                               % (a.status, p.status))
        metrics["body_differs_from_baseline"] = p.body_sha256 != b.body_sha256
        return Verdict(True, 0.75, metrics,
                       "摘掉令牌后同一请求仍返回 %d（带令牌时也是 %d）：令牌不是放行条件。"
                       "没做匿名对照，所以不能排除这个接口本来就不需要身份"
                       % (p.status, b.status))


class StoredMarkerReflected(Oracle):
    """存储型 XSS：写进去的标记，在**另一个请求**里被原样渲染。

    只做"写-读"两段，因为只有回读能区分"存下来了"和"只是回显"：
    - 写接口把内容回显在响应里但没落库 → 回读拿不到（0.10）；
    - 落库了但输出时转义 → 回读拿得到，但 `<` 变成 `&lt;`（0.15）；
    - 落库且原样输出在 HTML 里 → 0.92；
    - 输出在 JSON 里 → 0.35：浏览器不会把 JSON 当 HTML 解析，
      要再有一个前端把它塞进 innerHTML 才谈得上 XSS。
    """

    name = "stored_marker_reflected"
    min_level = "L2"

    @dataclass
    class Args:
        marker_pattern: str = r"pta[0-9a-z]{8}"
        html_types: Tuple[str, ...] = ("text/html", "application/xhtml")
        success_status: Tuple[int, ...] = (200, 201, 202, 204)
        # 标记必须还在标签体内：属性名是我们自己起的，撞车的概率可以忽略
        attr_name: str = "data-pta"

    def run(self, obs: Sequence[Observation], args: "StoredMarkerReflected.Args") -> Verdict:
        probes = _by_role(obs, "probe")
        verifies = _by_role(obs, "verify")
        if not probes:
            return Verdict(False, 0.0, {}, "缺少 probe 证据（写入请求）", ("probe",))
        p = probes[-1]
        metrics: Dict[str, Any] = {"probe_status": p.status, "probe_identity": p.identity,
                                   "probe_url": p.url}
        if p.status in (401, 403):
            return Verdict(False, 0.0, metrics, "写入被拒绝（%d），内容没进存储" % p.status)
        if p.status not in args.success_status:
            return Verdict(False, 0.15, metrics,
                           "写入没有被接受（%d）：谈不上存储" % p.status)
        if not verifies:
            return Verdict(False, 0.0, metrics,
                           "写完没有回读请求：写进去不等于别人能看到", ("verify",))

        v = verifies[-1]
        metrics.update({"verify_status": v.status, "verify_identity": v.identity,
                        "verify_url": v.url, "verify_content_type": v.content_type})
        if v.status in (401, 403):
            return Verdict(False, 0.10, metrics, "回读被拒绝（%d）" % v.status)
        if v.status not in args.success_status:
            return Verdict(False, 0.10, metrics,
                           "回读没有正常响应（%d）：标记可能存到了别处" % v.status)

        pat = re.compile(args.marker_pattern)
        in_verify = pat.search(v.text)
        metrics["marker_in_verify"] = bool(in_verify)
        metrics["marker_in_probe_echo"] = bool(pat.search(p.text))
        if not in_verify:
            echo = "（写响应里回显了标记，但回读没有：只回显、没落库）" \
                if metrics["marker_in_probe_echo"] else ""
            return Verdict(False, 0.10, metrics, "回读里没有本次写入的标记%s" % echo)

        marker = in_verify.group(0)
        vtext = v.text
        idx = vtext.find(marker)
        window = vtext[max(0, idx - 300): idx + 300]
        escaped = ("&lt;" in window or "&gt;" in window
                   or "&quot;" in window or "&#" in window)
        looks_like_tag = ('%s="%s"' % (args.attr_name, marker)) in window and "<img" in window
        ctype = (v.content_type or "").lower()
        is_html = any(t in ctype for t in args.html_types)
        metrics.update({"marker": marker, "escaped": escaped, "in_tag": looks_like_tag,
                        "is_html": is_html})

        # 先看回读的**类型**：JSON 里的标记不会被执行，这时候再谈转义、
        # 谈"在不在标签结构里"都是错的问题（JSON 序列化本来就会把引号写成 \"，
        # 拿它去比对 data-pta="…" 一定是假，会把 0.35 误降成 0.30）。
        if not is_html:
            return Verdict(True, 0.35, metrics,
                           "标记原样存下来了，但回读类型是 %s：浏览器不会把 JSON 当 HTML 解析，"
                           "要另有前端把它插进页面才谈得上 XSS"
                           % (ctype.split(";")[0] or "unknown"))
        if escaped:
            return Verdict(False, 0.15, metrics,
                           "标记出现了但被 HTML 转义（&lt; / &#…）：浏览器不会把它当标签")
        if not looks_like_tag:
            return Verdict(False, 0.30, metrics,
                           "标记出现了、没被转义，但不在我们写入的标签结构里："
                           "多半是纯文本输出，不构成 XSS")
        return Verdict(True, 0.92, metrics,
                       "写入的标记在回读页面里原样渲染（%s）：存储型 XSS 成立，"
                       "任何打开这个页面的会话都会执行它"
                       % (ctype.split(";")[0] or "html"))


class BatchUnauthorizedRead(Oracle):
    """批量读：同一身份连续读相邻对象，看能读通多少个。

    单个对象读得到说明不了什么 —— 可能本来就是公开资源，也可能正好是这个
    身份自己的。只有"一整片相邻对象都读得通"才说明详情/列表接口没做对象级
    授权，所以判据是比例，不是某一发。

    反证照旧，而且比单对象更要紧：
      - 不存在的对象也返回同样内容（decoy）→ 响应与 id 无关；
      - 几个不同 id 的响应彼此几乎一样 → 同上，读到的不是各自的对象。
    这两种都不算越权，哪怕比例是 100%。
    """

    name = "batch_unauthorized_read"
    min_level = "L1"

    @dataclass
    class Args:
        success_status: Tuple[int, ...] = (200,)
        all_open_ratio: float = 0.9
        half_open_ratio: float = 0.5
        similar_ratio: float = 0.98
        sample_size: int = 3

    def run(self, obs, args):
        base = _by_role(obs, "baseline")
        rows = _by_role(obs, "probe") + _by_role(obs, "sweep")
        if not rows:
            return Verdict(False, 0.0, {}, "缺少批量读的证据", ("probe",))
        if not base:
            return Verdict(False, 0.0, {},
                           "缺少 baseline 证据：不知道这个接口对当前身份是否正常",
                           ("baseline",))
        b = base[0]
        if b.status not in args.success_status:
            return Verdict(False, 0.0, {"baseline_status": b.status},
                           "baseline 没成功（%d）：这次测试不成立" % b.status)

        ok = [o for o in rows if o.status in args.success_status]
        ratio = len(ok) / float(len(rows))
        metrics: Dict[str, Any] = {
            "total": len(rows),
            "readable": len(ok),
            "ratio": round(ratio, 3),
            "statuses": [o.status for o in rows],
            "first_urls": [o.url for o in rows][:3],
        }
        if not ok:
            return Verdict(False, 0.0, metrics,
                           "%d 个相邻对象一个都没读到（全部 %s）：这个接口有对象级授权"
                           % (len(rows), sorted({o.status for o in rows})))

        decoy = _by_role(obs, "decoy")
        if decoy:
            d = decoy[0]
            if d.status in args.success_status \
                    and _sim(d.body, ok[0].body) >= args.similar_ratio:
                metrics["decoy_status"] = d.status
                return Verdict(False, 0.30, metrics,
                               "不存在的对象也返回了同样的内容：响应与对象 id 无关，"
                               "读得到不等于读到了别人的对象")

        sample = ok[:max(2, args.sample_size)]
        if len(sample) >= 2:
            pairs = [(sample[i], sample[j])
                     for i in range(len(sample)) for j in range(i + 1, len(sample))]
            avg = sum(_sim(x.body, y.body) for x, y in pairs) / float(len(pairs))
            metrics["body_similarity"] = round(avg, 3)
            if avg >= args.similar_ratio:
                return Verdict(False, 0.35, metrics,
                               "%d 个不同 id 的响应几乎一样（相似度 %.3f）："
                               "返回的不是各自的对象，读得到也不算越权"
                               % (len(sample), avg))

        if ratio >= args.all_open_ratio:
            return Verdict(True, 0.90, metrics,
                           "%d/%d 个相邻对象都能读：这个身份能读到一整片不属于它的对象"
                           % (len(ok), len(rows)))
        if ratio >= args.half_open_ratio:
            return Verdict(True, 0.86, metrics,
                           "%d/%d 个相邻对象能读：比例不低于一半，对象级授权基本没做"
                           % (len(ok), len(rows)))
        return Verdict(False, 0.65, metrics,
                       "只有 %d/%d 个相邻对象能读：个别可读，可能是公开对象或自己的，"
                       "不足以说明能读别人的" % (len(ok), len(rows)))


class NumericBoundaryAccepted(Oracle):
    """业务逻辑边界：越界数值被原样接受并存了下来。

    判据只有一个，但很硬：**回读里出现了我们塞进去的那个值**，原样、没被
    夹紧、没被改符号。那意味着服务端把它当合法值落库了 —— 至于是不是能
    换成钱，那是业务后果，不是这一层要证明的。

    反证三条：baseline 本身不成立（接口不通）；probe 被 400/422 拒（校验
    在起作用）；回读里没有那个值（被夹紧、被丢弃、或写根本没生效）。
    """

    name = "numeric_boundary_accepted"
    min_level = "L2"

    @dataclass
    class Args:
        expect_value: str = "-100"
        success_status: Tuple[int, ...] = (200, 201, 202, 204)
        reject_status: Tuple[int, ...] = (400, 409, 422)

    def run(self, obs, args):
        base = _by_role(obs, "baseline")
        probe = _by_role(obs, "probe")
        readback = _by_role(obs, "verify") + _by_role(obs, "baseline+verify")
        if not base or not probe:
            return Verdict(False, 0.0, {}, "缺少 baseline 或 probe 证据",
                           ("baseline", "probe") if not base else ("probe",))
        b, p = base[0], probe[0]
        metrics: Dict[str, Any] = {
            "expect_value": args.expect_value,
            "baseline_status": b.status,
            "probe_status": p.status,
        }
        if b.status not in args.success_status:
            return Verdict(False, 0.0, metrics,
                           "baseline 没成功（%d）：这次测试不成立" % b.status)
        if p.status in args.reject_status:
            return Verdict(False, 0.0, metrics,
                           "服务端拒绝了越界值（%d）：范围校验在起作用" % p.status)
        if p.status not in args.success_status:
            return Verdict(False, 0.10, metrics,
                           "probe 返回 %d：既不是明确的接受，也不是明确的拒绝" % p.status)
        if not readback:
            return Verdict(False, 0.0, metrics,
                           "写完没有回读：接口接受了请求，不等于把值存了下来",
                           ("verify",))
        r = readback[0]
        metrics["readback_status"] = r.status
        if r.status not in args.success_status:
            return Verdict(False, 0.10, metrics,
                           "回读没成功（%d）：看不到存下来的值" % r.status)
        if args.expect_value not in r.text:
            return Verdict(False, 0.15, metrics,
                           "回读里没有出现 %s：值被夹紧、被丢弃，或写入没生效"
                           % args.expect_value)
        # 0.86 而不是 0.80：passed=True 必须落在 confirmed 区间（0.85 以上），
        # 否则输出会长成「通过 / hypothesis」，自己和自己打架。
        return Verdict(True, 0.86, metrics,
                       "回读里原样出现了 %s：越界值被当合法值存了下来" % args.expect_value)


ORACLE_REGISTRY: Dict[str, type] = {
    DifferentialObjectAccess.name: DifferentialObjectAccess,
    BooleanResponseSplit.name: BooleanResponseSplit,
    ErrorSignatureMatch.name: ErrorSignatureMatch,
    FileSignatureMatch.name: FileSignatureMatch,
    OobCallbackReceived.name: OobCallbackReceived,
    RedirectTargetMatch.name: RedirectTargetMatch,
    JwtAcceptanceCheck.name: JwtAcceptanceCheck,
    AuthzTemplateDiff.name: AuthzTemplateDiff,
    DomMarkerPresent.name: DomMarkerPresent,
    FieldEscalationEffect.name: FieldEscalationEffect,
    TimingDistributionShift.name: TimingDistributionShift,
    WriteEffectVisible.name: WriteEffectVisible,
    InternalServiceFingerprint.name: InternalServiceFingerprint,
    UploadReadback.name: UploadReadback,
    DeserializationMarkerPresent.name: DeserializationMarkerPresent,
    IdempotencyViolation.name: IdempotencyViolation,
    CsrfTokenNotEnforced.name: CsrfTokenNotEnforced,
    StoredMarkerReflected.name: StoredMarkerReflected,
    BatchUnauthorizedRead.name: BatchUnauthorizedRead,
    NumericBoundaryAccepted.name: NumericBoundaryAccepted,
}


def build_oracle(name: str, args: Optional[Dict[str, Any]] = None) -> Oracle:
    cls = ORACLE_REGISTRY.get(name)
    if cls is None:
        raise KeyError("未注册的 oracle：%s" % name)
    if args is not None:
        cls.Args(**args)  # 未知键在加载期直接抛 TypeError
    return cls()
