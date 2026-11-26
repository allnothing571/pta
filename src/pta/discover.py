# -*- coding: utf-8 -*-
"""接口发现：从一个首页走到"这一串命令可以跑了"。

`pta crawl` 已经有了（BFS 抓页面、抽链接/表单/JS 端点），`pta plan` 也有了（参数名
命中规则 → 候选）。但真正对着一个目标坐下来的时候，中间还隔着一层手工活：
先 crawl 一次、再 plan 一次、然后对着候选 JSON 一个个拼 `pta run` 命令，拼的时候还要
回去查"这个模板要不要两个身份"。

`discover` 就是把这三步合成一条命令，并且补上原来没人回答的两个问题：

1. **为什么这个端点没有候选？** —— 参数名不命中规则（`?tab=info`）、无参端点、
   方法不在写方法集，三种都要说出来。不然"扫了一圈没东西"和"扫了一圈但漏了"长得一样。
2. **这条候选还差什么？** —— 要两个身份但工作区里只有零个。缺什么写在 blockers 里，
   命令照样给出来（占位符顶着），补上身份就能直接跑。

只读不写：一次 discover 的全部请求都花在 crawl 上（只发 GET），
不额外探测方法、不试参数、不发写请求。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import vhx
from .planner import MAX_GRAPH_SLOTS, Asset, PlannerState, heuristic_candidates
from .recon import Recon, ReconReport

MAX_ASSETS = 200

# 这些参数的值不进候选命令：命令会被复制进终端、贴进记录，值留在里面等于把
# 会话搬了一次家。名字命中就只留 `k=`，别的参数（id、page、q）保留真值——
# 不保留真值的话，生成的命令打的是一个空参数，测的就不是原来那个接口。
_SECRET_PARAMS = ("token", "csrf", "xsrf", "session", "auth", "key", "secret",
                  "password", "passwd", "sig", "signature", "apikey", "api_key",
                  "jwt", "bearer", "ticket")


def _safe_url(url: str) -> str:
    """抹掉 query 里的凭证类参数值，其余原样保留。"""
    parsed = urlsplit(url)
    if not parsed.query:
        return url
    kept = [(k, "" if any(s in k.lower() for s in _SECRET_PARAMS) else v)
            for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit(parsed._replace(query=urlencode(kept, doseq=True)))


def _valued_params(url: str) -> int:
    """这条 URL 里有几个查询参数是**带值**的。

    为什么要数：同一个接口页面可能先发 `?id=` 再发 `?id=7`，两次形状不同但去处
    相同。留哪一条决定了候选命令能不能直接打，也决定了图上有不有对象槽。
    """
    return sum(1 for _k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True) if v)


def _assets_from_calls(calls: Sequence[Dict[str, Any]],
                       identity: str = "none") -> List[Asset]:
    """把浏览器抓到的请求形状转成 Planner 认的资产。

    只收 http(s)，按「方法 + 去掉 query 的路径」去重；同名接口被页面调了
    三次就是 hits=3，那正是它重要的证据。

    合并规则（三个都要，缺一个都会丢信息）：

    - **URL 留带真值的那条**。`?id=` 和 `?id=7` 是同一件事的两次观测，
      但要拿来打的是后者：空值的命令改的是空气，图上也没有对象槽可外推。
    - **参数名取并集**。同一条接口两次调用可能带不同参数（A 屏带 `tab`、B 屏带
      `sort`），取第一条会漏掉另一个参数名，也就漏掉一条规则命中。
    - **正文一律不带**。请求体里有会话和个人信息，字段名在白名单里已经
      由 `body_fields()` 摘出来了，原样搬进资产没必要。
    """
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for call in calls or ():
        raw_url = str(call.get("url") or "")
        if not raw_url.startswith(("http://", "https://")):
            continue
        method = str(call.get("method") or "GET").upper()
        url = _safe_url(raw_url)
        key = (method, url.split("?")[0])
        names = tuple(call.get("query_names") or ())
        fields = tuple(call.get("body_fields") or ())
        status = int(call.get("status") or 0)
        slot = merged.get(key)
        if slot is None:
            merged[key] = {"url": url, "params": set(names), "body_params": set(fields),
                           "status": status, "content_type": call.get("mime") or None,
                           "hits": 1, "valued": _valued_params(url)}
            continue
        slot["hits"] += 1
        slot["params"].update(names)
        slot["body_params"].update(fields)
        if status:
            slot["status"] = status
        if not slot["content_type"] and call.get("mime"):
            slot["content_type"] = call.get("mime")
        valued = _valued_params(url)
        if valued > slot["valued"]:
            slot["url"], slot["valued"] = url, valued
    out: List[Asset] = []
    for (method, _base), slot in merged.items():
        out.append(Asset(
            url=slot["url"], method=method,
            params=tuple(sorted(slot["params"])),
            status=int(slot["status"] or 0), content_type=slot["content_type"],
            identity=identity, hits=int(slot["hits"]),
            body_params=tuple(sorted(slot["body_params"]))))
    return out



def harvest_assets(ws, url: str, identity: str = "none", limit: int = 60,
                   settle: float = 2.0,
                   wait_for: Optional[str] = None) -> Tuple[List[Asset], Dict[str, Any]]:
    """开一次真浏览器打开 `url`，把页面自己发出的请求变成资产。

    返回 `(assets, info)`。起不来浏览器不是异常——沙箱里这是常态，
    调用方拿 info 里的 reason 说话，剩下的照常按证据出候选。
    """
    from .browser import NavRequest
    from .workspace import attach_browser, close_browser

    info: Dict[str, Any] = {"ok": False, "calls": 0, "assets": 0, "reason": ""}
    try:
        attach_browser(ws)
    except Exception as exc:       # 起不来就是起不来，连带发现一起失败不划算
        info["reason"] = "浏览器起不来：%s" % exc
        return [], info
    if getattr(ws, "browser", None) is None:
        info["reason"] = "浏览器起不来（沙箱内需提权）"
        return [], info
    try:
        res = ws.browser.navigate(NavRequest(
            url=url, identity=identity, harvest=True, harvest_limit=limit,
            settle_s=settle, wait_for=wait_for))
    except Exception as exc:       # 同上：浏览器崩了，HTTP 那一路的结果还在
        info["reason"] = "导航失败：%s" % exc
        return [], info
    finally:
        close_browser(ws)
    if res.status != "ok":
        info["reason"] = "导航失败：%s" % (res.reason or res.status)
        return [], info
    assets = _assets_from_calls(res.harvest_calls, identity=identity)
    info.update({"ok": True, "calls": len(res.harvest_calls), "assets": len(assets),
                 "final_url": res.final_url,
                 "evidence_id": res.evidence_id})
    return assets, info


_LOGIN_SEGMENTS = frozenset({"login", "signin", "sign-in", "signon", "sign-on", "sso",
                             "authorize", "auth"})


def _loginish(url: str) -> bool:
    """看着像登录页吗：路径里有一整段叫 login / signin / sso 之类。

    只看路径段，不看 query 也不看页面内容——cookie 过期时服务端往往就是
    302 到这个玩意儿，而这一条判断不花一次请求。
    """
    path = urlsplit(url or "").path.lower()
    return any(seg in _LOGIN_SEGMENTS for seg in path.split("/") if seg)


def _path_key(url: str) -> str:
    parts = urlsplit(url or "")
    return (parts.path or "/").rstrip("/") or "/"


def _diagnose(report: "Report") -> List[str]:
    """为什么停在这儿。只写句柄上看得出来的事，不猜。

    自用工具的第三条验收是「它停了我知道为什么停」，而最常见的停法就是
    登录态掉了：爬取 0 页、浏览器只发 1 条请求、图连不出边——三个数字都对，
    但不说原因等于没说。
    """
    out: List[str] = []
    b = report.browser or {}
    seed = report.seeds[0] if report.seeds else ""
    final = b.get("final_url") or ""
    who = report.identities[0] if report.identities else ""

    if final and seed:
        if _loginish(final) and not _loginish(seed):
            out.append("身份 %s 像是没登进去：浏览器打开 %s 被弹到 %s；先确认一遍 %s"
                       % (who or "（无身份）", _short(seed, 40), _short(final, 44),
                          _auth_check_hint(seed, who)))
        elif _path_key(final) != _path_key(seed):
            out.append("浏览器落地在 %s（和 seed 不是同一个地址，被重定向了）"
                       % _short(final, 52))

    pages = len(report.crawl.pages) if report.crawl else 0
    calls = int(b.get("calls") or 0)
    if report.crawl is not None:
        # 只有 seed 自己跟不过去、或者一页都没抓到，才把这一跳当成"停下来的原因"。
        # 爬取成功时页面上有个坏链接是常态，拿它当理由是假警报。
        for br in report.crawl.blocked_redirects[:3]:
            if not (br.get("seed") or pages == 0):
                continue
            target = br.get("target", "")
            fixed = _port_restore(br.get("url", ""), target)
            out.append("站点把 %s 跳到 %s，那一跳没跟成（%s）；想继续就把 --seed 换成 %s 再跑"
                       % (_short(br.get("url", ""), 40), _short(target, 44),
                          br.get("reason", "越界"), fixed))
        landed = next((p for p in report.crawl.pages if p.final_url), None)
        if landed is not None and _loginish(landed.final_url) and not _loginish(landed.url):
            out.append("身份 %s 像是没登进去：%s 被弹到 %s；先确认一遍 %s"
                       % (who or "（无身份）", _short(landed.url, 40),
                          _short(landed.final_url, 44),
                          _auth_check_hint(seed or landed.url, who)))
    if report.crawl is not None and pages == 0:
        why = ""
        if report.crawl.skipped:
            tally: Dict[str, int] = {}
            for s in report.crawl.skipped:
                r = s.get("reason") or "未知"
                tally[r] = tally.get(r, 0) + 1
            why = "，" + "、".join("%s ×%d" % (k, v) for k, v in sorted(tally.items()))
        out.append("爬取一页都没成（%d 发请求%s）"
                   % (max(0, report.requests - calls), why))

    if b.get("ok") and calls <= 2 and not (report.graph or {}).get("edges"):
        out.append("页面几乎没发自己的请求（%d 条），图也连不出边——"
                   "停在登录页、或者 JS 没跑起来时就是这个样子" % calls)
    return out


def _auth_check_hint(seed: str, who: str) -> str:
    base = seed.rstrip("/") + "/"
    return ("python -m pta.cli auth check --identity %s --url %s"
            "（换 cookie 用 auth add --cookie-file）" % (who or "IDENTITY_A", base))


def _port_restore(original: str, target: str) -> str:
    """站点拼绝对地址时把端口弄丢了，给它补回去。

    只补一种情况：同一个主机、目标没写端口、原地址用的是非默认端口。
    目标明写了别的端口就是站点自己的意图，不替它改。
    """
    o, t = urlsplit(original or ""), urlsplit(target or "")
    if not o.hostname or (o.hostname or "").lower() != (t.hostname or "").lower():
        return target
    oport = o.port or (443 if o.scheme == "https" else 80)
    tport = t.port or (443 if t.scheme == "https" else 80)
    if t.port is not None or oport == tport:
        return target
    netloc = "%s:%d" % (o.hostname, oport)
    return urlunsplit((t.scheme or o.scheme, netloc, t.path or "/", t.query, ""))


@dataclass
class Needs:
    baseline: bool = False
    probe: bool = False

    def to_json(self) -> Dict[str, bool]:
        return {"baseline": self.baseline, "probe": self.probe}

    @property
    def count(self) -> int:
        return int(self.baseline) + int(self.probe)


@dataclass
class Suggestion:
    url: str
    template_id: str
    title: str
    param_path: str
    method: str
    priority: float
    rationale: str
    needs: Needs
    blockers: List[str] = field(default_factory=list)
    # rule = 参数名/方法/身份这类直接规则；graph = 从资产图外推一步。
    # 报告里要能分开看：外推的置信度天然低一档，别和规则命中混在一起数。
    source: str = "rule"

    def command(self, root: str, identities: Sequence[str]) -> str:
        # URL 和路径都加双引号：PowerShell 里 ? & 是保留字符，路径里有空格时更必须
        parts = ["python -m pta.cli run", "--root", '"%s"' % root,
                 "--template", self.template_id, '--url "%s"' % self.url]
        if self.param_path and self.param_path != "body:*":
            parts += ["--param", self.param_path]
        if self.param_path == "body:*":
            parts += ["--param", "body:*"]
        if self.method and self.method.upper() != "GET":
            parts += ["--method", self.method.upper()]
        if self.needs.baseline:
            who = identities[0] if len(identities) > 0 else "IDENTITY_A"
            parts += ["--identity-baseline", who]
        if self.needs.probe:
            who = identities[1] if len(identities) > 1 else "IDENTITY_B"
            parts += ["--identity-probe", who]
        return " ".join(parts)

    def to_json(self) -> Dict[str, Any]:
        return {"url": self.url, "template_id": self.template_id, "title": self.title,
                "param_path": self.param_path, "method": self.method,
                "priority": round(self.priority, 3), "rationale": self.rationale,
                "needs": self.needs.to_json(), "blockers": list(self.blockers),
                "source": self.source}


@dataclass
class Gap:
    """一个有端点但没候选的地方。必须解释，否则「没发现」和「漏了」看不出区别。"""

    url: str
    method: str
    params: Tuple[str, ...]
    reason: str

    def to_json(self) -> Dict[str, Any]:
        return {"url": self.url, "method": self.method,
                "params": list(self.params), "reason": self.reason}


@dataclass
class Report:
    seeds: Tuple[str, ...]
    crawl: Optional[ReconReport]
    suggestions: List[Suggestion] = field(default_factory=list)
    gaps: List[Gap] = field(default_factory=list)
    identities: Tuple[str, ...] = ()
    requests: int = 0
    # 浏览器通道的结果：ok / calls / assets / reason。None 表示这次没走浏览器。
    browser: Optional[Dict[str, Any]] = None
    # 资产图摘要：{nodes, edges, kinds}。它是"外推候选从哪来"的依据。
    graph: Optional[Dict[str, Any]] = None
    # 为什么停在这儿：登录态掉了、爬取全跳过、页面一条请求都没发……
    diagnostics: List[str] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        crawl = None
        if self.crawl is not None:
            crawl = {"pages": len(self.crawl.pages),
                     "requests": self.crawl.requests,
                     "skipped": list(self.crawl.skipped),
                     "blocked_redirects": list(self.crawl.blocked_redirects)}
        return {
            "seeds": list(self.seeds),
            "requests": self.requests,
            "identities": list(self.identities),
            "browser": self.browser,
            "graph": self.graph,
            "crawl": crawl,
            "diagnostics": list(self.diagnostics),
            "counts": {
                "pages": len(self.crawl.pages) if self.crawl else 0,
                "endpoints": len({s.url for s in self.suggestions}) + len(self.gaps),
                "suggestions": len(self.suggestions),
                "blocked": sum(1 for s in self.suggestions if s.blockers),
                "harvested": (self.browser or {}).get("assets", 0),
                "graph_edges": (self.graph or {}).get("edges", 0),
                "graph_candidates": sum(1 for s in self.suggestions
                                        if s.source == "graph"),
            },
            "suggestions": [s.to_json() for s in self.suggestions],
            "gaps": [g.to_json() for g in self.gaps],
        }


def _needs(template: Dict[str, Any]) -> Needs:
    """这个模板要几个身份。判据在模板里，不在这里硬编码：
    要么 probe 动作是 swap_identity（两个身份读同一个对象），
    要么前置条件声明了 identity_available。"""
    needs = Needs()
    probe = template.get("probe") or {}
    for step in probe.get("sequence") or ():
        if step == "swap_identity":
            needs.probe = True
    if probe.get("action") == "swap_identity":
        needs.probe = True
    for pre in template.get("preconditions") or ():
        if pre.get("kind") != "identity_available":
            continue
        if pre.get("role") == "probe":
            needs.probe = True
        else:
            needs.baseline = True
    return needs


def _blockers(needs: Needs, identities: Sequence[str]) -> List[str]:
    out: List[str] = []
    if needs.count > len(identities):
        if not identities:
            out.append("这条要 %d 个身份，工作区里一个都没有（`pta auth add` 先搬进登录态）"
                       % needs.count)
        else:
            out.append("这条要 %d 个身份，工作区里只有 %d 个：%s"
                       % (needs.count, len(identities), "、".join(identities)))
    return out


def _templates() -> Dict[str, Dict[str, Any]]:
    return {t["id"]: t for t in vhx.TEMPLATES}


def _gap_reason(asset) -> Optional[str]:
    """这个端点为什么一个像样的候选都没出。返回 None 表示它确实出了候选。

    注意「无参 GET」不在这里：它本来就会得到 info-disclosure-artifact 这条兜底候选，
    再报一次只重复了 rationale。这里只报「看着有参数、其实一个都打不了」的情况。
    """
    if asset.params:
        return ("参数名都不命中规则（%s）：要么它真是无害的筛选参数，"
                "要么规则还没覆盖这种命名" % "、".join(asset.params))
    if asset.body_params:
        return ("请求体字段都不命中规则（%s）：写候选需要熟悉的字段名（name/role 这类）"
                % "、".join(asset.body_params))
    if asset.method.upper() not in ("GET", "HEAD"):
        return "写方法但没抓到请求体字段：写候选需要知道字段名（用 harvest 抓一次页面自己的请求）"
    return None


def _query_map(ws) -> Dict[Tuple[str, str], str]:
    """(无参 url, method) -> 第一次见到的 query 串。

    evidence 表里 `raw_path` 不含 query，`asset.url` 因此永远没有参数值；
    而 `--param query:id` 要改的正是那个值。所以候选的 url 必须自己把 query 补回来，
    否则生成的命令会对着一个没有 id 的 URL 跑，改了个空气。
    """
    from .models import canonical_query

    out: Dict[Tuple[str, str], str] = {}
    for row in ws.store.list_evidence(ws.scope.engagement_id):
        if row["method"] == "OOB":
            continue
        url = "%s://%s:%d%s" % (row["scheme"], row["host"], row["port"], row["raw_path"])
        key = (url, (row["method"] or "GET").upper())
        if key in out:
            continue
        pairs = [(str(p[0]), str(p[1])) for p in json.loads(row["query_json"] or "[]")]
        if pairs:
            out[key] = canonical_query(pairs)
    return out


def _fill_query(url: str, param_path: str, qmap: Dict[Tuple[str, str], str],
                method: str) -> str:
    if "?" in url or not param_path.startswith("query:"):
        return url
    q = qmap.get((url, (method or "GET").upper()))
    return url + "?" + q if q else url


def discover(ws, seeds: Sequence[str], max_pages: int = 25, max_depth: int = 2,
             identity: str = "none", crawl: bool = True,
             max_candidates: int = 30, browser: bool = False,
             browser_limit: int = 60, browser_settle: float = 2.0,
             browser_wait_for: Optional[str] = None,
             graph_slots: int = MAX_GRAPH_SLOTS) -> Report:
    """跑一轮发现。`crawl=False` 时只读工作区里已有的证据（省请求）。

    `browser=True` 会在 crawl 之后另开一次真浏览器，把页面**自己发出的**
    请求也当成资产。SPA 的链接和接口都在 JS 里，HTTP 爬只能拿到一个空壳；
    这一步拿的是浏览器真的打出去的东西，包括 query 名和请求体字段名。

    资产进来之后会建成一张邻接图（`planner.PlannerState.graph`），图上外推出
    「同一资源换个方法」「同模板换个对象」「引用/id 复用」三类候选。图外推
    最多占 `graph_slots` 个位子：它天然比规则命中弱一档，但不该被上百个
    规则候选整段挤掉——否则"抓到的调用喂给图"就等于没做。
    """
    seeds = tuple(seeds or ())
    report: Optional[ReconReport] = None
    if crawl:
        if not seeds:
            raise ValueError("要爬就得给种子 URL（--seed）")
        recon = Recon(ws, max_pages=max_pages, max_depth=max_depth, identity=identity)
        report = recon.run(seeds)

    extra: List[Asset] = []
    binfo: Optional[Dict[str, Any]] = None
    if browser:
        if not seeds:
            raise ValueError("要用浏览器就得给种子 URL（--seed）")
        extra, binfo = harvest_assets(ws, seeds[0], identity=identity,
                                     limit=browser_limit, settle=browser_settle,
                                     wait_for=browser_wait_for)

    state = PlannerState.collect(ws, max_assets=MAX_ASSETS, extra_assets=extra)
    raw = heuristic_candidates(state, max_candidates, graph_slots=graph_slots)

    tpls = _templates()
    identities = tuple(ws.vault.identities())
    out = Report(seeds=seeds, crawl=report, identities=identities,
                 requests=(report.requests if report else 0) + (binfo or {}).get("calls", 0),
                 browser=binfo, graph=state.graph.brief())

    covered: Dict[Tuple[str, str], int] = {}
    qmap = _query_map(ws)
    for cand in raw:
        tpl = tpls.get(cand.template_id) or {}
        needs = _needs(tpl)
        url = _fill_query(cand.url, cand.param_path or "", qmap, cand.method or "GET")
        out.suggestions.append(Suggestion(
            url=url, template_id=cand.template_id,
            title=tpl.get("title") or cand.template_id,
            param_path=cand.param_path or "", method=(cand.method or "GET"),
            priority=float(cand.priority or 0.0),
            rationale=getattr(cand, "rationale", "") or "",
            needs=needs, blockers=_blockers(needs, identities),
            source=getattr(cand, "source", "rule") or "rule"))
        key = (cand.url, (cand.method or "GET").upper())
        covered[key] = covered.get(key, 0) + 1

    for asset in state.assets:
        key = (asset.url, (asset.method or "GET").upper())
        if key in covered:
            continue
        reason = _gap_reason(asset)
        if reason:
            out.gaps.append(Gap(url=asset.url, method=asset.method or "GET",
                                params=tuple(asset.params) + tuple(asset.body_params),
                                reason=reason))
    out.diagnostics = _diagnose(out)
    return out


def render(report: Report, root: str) -> List[str]:
    """给人看的版本。表宽有限，所以分两段：能跑的、为什么没跑。"""
    lines: List[str] = []
    lines.append("爬取：%d 页 / %d 发请求；工作区身份：%s"
                 % (len(report.crawl.pages) if report.crawl else 0, report.requests,
                    "、".join(report.identities) or "（无）"))
    if report.browser is not None:
        b = report.browser
        if b.get("ok"):
            lines.append("浏览器：页面自己发了 %d 条请求，其中 %d 个接口进了候选池"
                         % (b.get("calls", 0), b.get("assets", 0)))
        else:
            lines.append("浏览器：没走通（%s）；下面的结果只来自 HTTP 爬取"
                         % (b.get("reason") or "未知原因"))
    if report.graph:
        g = report.graph
        kinds = g.get("kinds") or {}
        from_graph = sum(1 for s in report.suggestions if s.source == "graph")
        if kinds:
            detail = "、".join("%s %d" % (k, v) for k, v in sorted(kinds.items()))
            lines.append("资产图：%d 个资产、%d 条边（%s）；其中 %d 条候选是图上外推的"
                         % (g.get("nodes", 0), g.get("edges", 0), detail, from_graph))
        else:
            lines.append("资产图：%d 个资产，没有可连的边" % g.get("nodes", 0))
    if report.diagnostics:
        lines.append("")
        lines.append("为什么停在这儿：")
        for d in report.diagnostics:
            lines.append("  - " + d)
    lines.append("")
    if report.suggestions:
        lines.append("可以打的（按优先级）：")
        lines.append("  %-34s %-24s %-9s %-6s %s"
                     % ("端点", "模板", "参数位", "身份", "卡点"))
        for s in report.suggestions:
            tail = "、".join(s.blockers) if s.blockers else ""
            tpl = s.template_id + (" ≈" if s.source == "graph" else "")
            lines.append("  %-34s %-24s %-9s %-6s %s"
                         % (_short(s.url), tpl, s.param_path or "-",
                            "%d" % s.needs.count, tail))
        if any(s.source == "graph" for s in report.suggestions):
            lines.append("  ≈ 来自资产图外推（同资源换方法 / 同模板换对象 / 引用与 id 复用），"
                         "证据比规则命中弱一档")
        lines.append("")
        lines.append("复制就能跑：")
        for s in report.suggestions:
            lines.append("  " + s.command(root, report.identities))
    else:
        lines.append("没有产生任何候选。下面「没出候选的端点」说明了原因。")

    if report.gaps:
        lines.append("")
        lines.append("没出候选的端点（%d 个）：" % len(report.gaps))
        for g in report.gaps[:20]:
            lines.append("  %-38s %s" % (_short(g.url), g.reason))
        if len(report.gaps) > 20:
            lines.append("  …还有 %d 个" % (len(report.gaps) - 20))
    return lines


def _short(url: str, width: int = 34) -> str:
    if len(url) <= width:
        return url
    return url[: width - 1] + "…"


def write_report(ws, report: Report, name: str = "discover.json") -> str:
    import os

    path = os.path.join(ws.root, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_json(), fh, ensure_ascii=False, indent=2)
    return path
