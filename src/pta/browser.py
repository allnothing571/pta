"""真浏览器（headless Chromium via CDP）。

它和 http_probe 的地位一样：**都碰 socket，所以都必须过 Scope Kernel**。
浏览器多出来的风险是"页面自己会发请求"——一张图片、一段 fetch、一次 302，
都能把范围扩到授权域之外。所以范围校验挂在 `Fetch.requestPaused` 上，
对**每一个**子请求逐条判定，越界的直接 failRequest 并记 denied。

三层防护，缺一不可：
1. `--host-resolver-rules`：把授权域钉到我们解析出的 IP（等价于 DNS pin，防重绑定）。
2. `Fetch.requestPaused` 拦截：逐请求过 scope.check_url + ip_allowed。
3. 出口代理：scope 配了 egress_proxy 就 `--proxy-server`，浏览器自己无直连能力。

证据：一次导航产出一条 evidence，body 是 **DOM 快照**（不是原始响应字节），
并在 headers 里写 `X-Pta-Capture: dom-snapshot`。
这一点很重要：XSS 的判定对象是"执行后的 DOM"，原始响应里有没有 `<script>` 根本不说明问题。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from . import payloads
from .cdp import CdpError, CdpSession, WebSocket
from .errors import BudgetExceeded, PayloadRejected, ScopeViolation
from .harvest import Harvester, decode_body
from .models import Body, CanonicalRequest, Evidence, Header, sha256_hex
from .probe import compute_evidence_id
from .scope import DnsPin, Scope, check_request

_EXE_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)

_BASE_ARGS = (
    "--headless=new",
    "--disable-gpu",
    # 受限环境（容器/服务沙箱）里 Chrome 起子进程会撞上 Mojo 命名管道被拒
    # （`platform_channel.cc:112 Check failed: . : 拒绝访问 (0x5)`）。这一条能救
    # 一部分场景；连命名管道都不让建的场合只能换到普通终端里跑。
    "--no-sandbox",
    "--disable-crash-reporter",
    "--disable-breakpad",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--metrics-recording-only",
    "--mute-audio",
    "--remote-debugging-port=0",
    "--window-size=1280,900",
)


def find_browser(exe: Optional[str] = None) -> Optional[str]:
    for cand in (exe, os.environ.get("PTA_BROWSER")) + _EXE_CANDIDATES:
        if cand and os.path.exists(cand):
            return cand
    return None


@dataclass
class BrowserConfig:
    exe: str = ""                        # 留空则用 find_browser()（含 PTA_BROWSER）
    headless: bool = True
    allow_no_sandbox: bool = False       # 容器/受限环境里 Chromium 起不来时才开
    proxy: Optional[str] = None          # http://127.0.0.1:8080
    startup_timeout: float = 25.0
    extra_args: Tuple[str, ...] = ()
    keep_profile: bool = False


class BrowserProcess:
    """起停一个 headless Chromium，暴露 browser 级 CDP 会话。"""

    def __init__(self, cfg: BrowserConfig, profile_dir: Optional[str] = None):
        self.cfg = cfg
        self.profile_dir = profile_dir or tempfile.mkdtemp(prefix="pta-browser-")
        self._owns_profile = profile_dir is None
        self.proc: Optional[subprocess.Popen] = None
        self.session: Optional[CdpSession] = None
        self.product = ""

    def start(self) -> "BrowserProcess":
        exe = self.cfg.exe or find_browser()
        if not exe:
            raise CdpError("找不到 Chrome/Edge；用 PTA_BROWSER 指定可执行文件路径")
        args = [exe] + [a for a in _BASE_ARGS if self.cfg.headless or a != "--headless=new"]
        args += ["--user-data-dir=" + self.profile_dir, "--remote-debugging-port=0"]
        if self.cfg.allow_no_sandbox:
            args += ["--no-sandbox", "--disable-setuid-sandbox"]
        if self.cfg.proxy:
            args.append("--proxy-server=" + self.cfg.proxy)
        args += list(self.cfg.extra_args)
        args.append("about:blank")
        self._log_path = os.path.join(self.profile_dir, "chrome.log")
        try:
            self._log = open(self._log_path, "wb")
        except OSError:
            self._log = None
        # 不能用 PIPE：受限环境里子进程开不了命名管道，Chrome 连自己的 Mojo IPC
        # 都建不起来（`platform_channel.cc:112 Check failed: . : 拒绝访问 (0x5)`），
        # 主进程跟着崩溃。日志写到 profile 目录里，退出时再读回来。
        self.proc = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                     stdout=self._log or subprocess.DEVNULL,
                                     stderr=subprocess.STDOUT)
        port, path = self._wait_endpoint()
        self.session = CdpSession(WebSocket("127.0.0.1", port, path, timeout=30))
        try:
            self.product = str(self.session.call("Browser.getVersion")["product"])
        except (CdpError, KeyError):
            self.product = "chromium"
        return self

    def _wait_endpoint(self) -> Tuple[int, str]:
        assert self.proc is not None
        port_file = os.path.join(self.profile_dir, "DevToolsActivePort")
        deadline = time.time() + self.cfg.startup_timeout
        while time.time() < deadline:
            if os.path.exists(port_file):
                lines = open(port_file).read().split("\n")
                if len(lines) >= 2 and lines[0].strip().isdigit():
                    return int(lines[0]), lines[1].strip()
            if self.proc.poll() is not None:
                raise CdpError("浏览器进程提前退出（exit=%s）：%s"
                               % (self.proc.returncode, self._tail_output()))
            time.sleep(0.15)
        self.stop()
        raise CdpError("等不到 DevToolsActivePort（%.0fs）；受限环境下需要 "
                       "allow_no_sandbox=True 或改用单进程模式" % self.cfg.startup_timeout)

    def _tail_output(self) -> str:
        if not getattr(self, "_log_path", "") or not os.path.exists(self._log_path):
            return ""
        try:
            with open(self._log_path, "rb") as fh:
                out = fh.read()[-20000:]
        except OSError:
            return ""
        text = out.decode("utf-8", "replace").strip().splitlines()
        keep = [l for l in text if "ERROR" in l or "FATAL" in l][-4:]
        return " | ".join(keep)[:600]

    def stop(self) -> None:
        if self.session is not None:
            try:
                self.session.close()
            except OSError:
                pass
            self.session = None
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
        if getattr(self, "_log", None) is not None:
            try:
                self._log.close()
            except OSError:
                pass
            self._log = None
        if self._owns_profile and not self.cfg.keep_profile:
            shutil.rmtree(self.profile_dir, True)

    def __enter__(self) -> "BrowserProcess":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


@dataclass
class NavRequest:
    url: str
    label: str = "browser"
    param_path: Optional[str] = None
    payload_class: Optional[str] = None
    payload_variant: Optional[str] = None
    identity: str = "none"
    level: Optional[str] = None
    settle_s: float = 1.2
    wait_for: Optional[str] = None        # 额外等待的 JS 条件表达式
    screenshot: bool = False
    asset_node_id: Optional[str] = None
    harvest: bool = False                 # 顺手把页面自己发的接口调用记下来
    harvest_limit: int = 12               # 每条导航最多记几条（按形状去重后）


@dataclass
class NavResult:
    status: str                            # ok | denied | blocked | error
    reason: str = ""
    evidence_id: Optional[str] = None
    final_url: str = ""
    body_sha256: str = ""
    dom_sha256: str = ""
    console: List[str] = field(default_factory=list)
    denied_urls: List[str] = field(default_factory=list)
    requests_allowed: int = 0
    elapsed_ms: int = 0
    harvested: List[str] = field(default_factory=list)     # harvest 证据 id
    harvest_calls: List[Dict[str, Any]] = field(default_factory=list)


class BrowserTool:
    """把一次导航变成一条证据，并把越界子请求挡在门外。"""

    def __init__(self, scope: Scope, store: Any, cas: Any, budget: Any,
                 page_session: CdpSession, page_id: str, target_id: str,
                 product: str = "chromium", dns: Optional[DnsPin] = None,
                 bus: Any = None, vault: Any = None):
        self.scope = scope
        self.store = store
        self.cas = cas
        self.budget = budget
        self.vault = vault
        self.s = page_session
        self.page_id = page_id
        self.target_id = target_id
        self.product = product
        self.dns = dns or DnsPin()
        self.bus = bus
        self.denied: List[str] = []
        self.allowed_count = 0
        self._console: List[str] = []
        self._exc: List[str] = []
        self.harvest: Optional[Harvester] = None
        self.s.handler = self._on_cdp_event

    # ---------- 网络层范围校验 ----------
    def _on_cdp_event(self, msg: Dict[str, Any]) -> None:
        method = msg.get("method", "")
        params = msg.get("params", {}) or {}
        if method == "Fetch.requestPaused":
            self._on_request_paused(params)
        elif method.startswith("Network."):
            if self.harvest is not None:
                self.harvest.on_event(method, params)
        elif method == "Runtime.consoleAPICalled":
            self._console.append(self._console_text(params))
        elif method == "Runtime.exceptionThrown":
            det = params.get("exceptionDetails", {}) or {}
            self._exc.append(str(det.get("text") or det.get("exception", {}).get("description", ""))[:300])
        elif method == "Log.entryAdded":
            entry = params.get("entry", {}) or {}
            self._console.append("[%s] %s" % (entry.get("level", "log"), str(entry.get("text", ""))[:300]))

    def _on_request_paused(self, params: Dict[str, Any]) -> None:
        rid = params.get("requestId")
        req = params.get("request", {}) or {}
        url = str(req.get("url", ""))
        if url.startswith(("data:", "about:", "blob:", "chrome:", "devtools:")):
            self._continue(rid)
            return
        try:
            method = str(req.get("method", "GET")).upper()
            check_request(self.scope, method, url, "L1")
            host = urlsplit(url).hostname or ""
            if host:
                ip = self.dns.pin(host, self.scope)      # 解析+IP 白名单，双保险
                del ip
        except ScopeViolation as exc:
            self.denied.append(url)
            self.s.send("Fetch.failRequest",
                        {"requestId": rid, "errorReason": "BlockedByClient"},
                        session=self.page_id)
            self._log_denied(url, str(exc))
            return
        except Exception as exc:                          # 解析失败也当越界
            self.denied.append(url)
            self.s.send("Fetch.failRequest",
                        {"requestId": rid, "errorReason": "BlockedByClient"},
                        session=self.page_id)
            self._log_denied(url, "resolve_failed:%s" % exc)
            return
        self.allowed_count += 1
        self._continue(rid)

    def _continue(self, rid: Any) -> None:
        self.s.send("Fetch.continueRequest", {"requestId": rid}, session=self.page_id)

    def _log_denied(self, url: str, reason: str) -> None:
        self.store.log_action(engagement_id=self.scope.engagement_id, tool="browser_nav",
                              host=urlsplit(url).hostname or "", url=url,
                              decision="denied", reason=reason,
                              level="L1", approval_fp="",
                              detail={"via": "fetch_interception"})
        if self.bus is not None:
            self.bus.publish({"type": "scope_denied", "tool": "browser_nav", "url": url,
                              "reason": reason})

    @staticmethod
    def _console_text(params: Dict[str, Any]) -> str:
        bits = []
        for arg in params.get("args", []) or []:
            val = arg.get("value")
            if val is None:
                val = arg.get("description") or arg.get("unserializableValue") or arg.get("type")
            bits.append(str(val)[:200])
        return " ".join(bits)[:400]

    # ---------- 导航 ----------
    def _apply_identity(self, identity: str, origin: str) -> None:
        """把 vault 里这个身份搬进浏览器。

        不搬的话 `--identity A` 打开的仍是匿名页面：SPA 抓到的接口全在登录墙外，
        或者干脆全被 302 到登录页，harvest 出来的东西一个都用不上。
        cookie 拆成逐条 setCookie（浏览器的 cookie 容器是按名字存的，整条塞不进去），
        其余头走 setExtraHTTPHeaders。
        """
        if not identity or identity == "none" or self.vault is None:
            return
        try:
            items = dict(self.vault.items("cred/%s/" % identity))
        except Exception:            # vault 读不出来不该让导航失败
            return
        if not items:
            return
        try:
            self.s.call("Network.enable", {}, session=self.page_id, timeout=5)
        except CdpError:
            pass
        extra: Dict[str, str] = {}
        for ref, value in items.items():
            name = ref.rsplit("/", 1)[-1]
            if name.lower() == "cookie":
                for part in str(value).split(";"):
                    part = part.strip()
                    if not part or "=" not in part:
                        continue
                    key, val = part.split("=", 1)
                    try:
                        self.s.call("Network.setCookie",
                                    {"name": key.strip(), "value": val.strip(),
                                     "url": origin, "path": "/"},
                                    session=self.page_id, timeout=5)
                    except CdpError as exc:
                        self._exc.append("setCookie %s 失败：%s" % (key.strip(), exc))
                continue
            extra[name] = str(value)
        if not extra:
            return
        try:
            self.s.call("Network.setExtraHTTPHeaders", {"headers": extra},
                        session=self.page_id, timeout=5)
        except CdpError as exc:
            self._exc.append("setExtraHTTPHeaders 失败：%s" % exc)

    def navigate(self, req: NavRequest) -> NavResult:
        started = time.time()
        level = req.level or (payloads.level_floor(req.payload_class) if req.payload_class else "L1")
        host, scheme, port, raw_path = check_request(self.scope, "GET", req.url, level)
        parsed = urlsplit(req.url)
        query: List[Tuple[str, str]] = list(parse_qsl(parsed.query, keep_blank_values=True))
        nonce = ""
        if req.payload_class and req.param_path:
            if not req.param_path.startswith("query:"):
                raise PayloadRejected("浏览器导航只支持 query 注入（收到 %s）" % req.param_path)
            name = req.param_path.split(":", 1)[1]
            nonce = payloads.nonce()
            value = payloads.render(req.payload_class, nonce_value=nonce)
            hit = False
            out: List[Tuple[str, str]] = []
            for k, v in query:
                if k == name:
                    out.append((k, value))
                    hit = True
                else:
                    out.append((k, v))
            if not hit:
                out.append((name, value))
            query = out
        from urllib.parse import urlencode
        nav_url = "%s://%s%s%s" % (scheme, host,
                                   "" if port in (80, 443) else ":%d" % port,
                                   raw_path + ("?" + urlencode(query) if query else ""))

        self.denied, self.allowed_count = [], 0
        self._console, self._exc = [], []
        self.harvest = None
        if req.harvest:
            self.harvest = Harvester(allowed_hosts=(host,), limit=req.harvest_limit)
        try:
            self.budget.take(host)
        except BudgetExceeded as exc:
            return NavResult("blocked", "budget:%s" % exc, final_url=nav_url)
        try:
            self.s.call("Page.enable", session=self.page_id)
            self.s.call("Runtime.enable", session=self.page_id)
        except CdpError:
            pass
        try:
            self.s.call("Log.enable", session=self.page_id, timeout=5)
        except CdpError:
            pass
        try:
            self.s.call("Fetch.enable",
                        {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
                        session=self.page_id)
        except CdpError as exc:
            return NavResult("error", "fetch.enable 失败：%s" % exc, final_url=nav_url)
        if req.harvest:
            try:
                # 只要事件，不要缓冲：正文按需再取，缓冲会把整页资源都留在浏览器内存里。
                self.s.call("Network.enable",
                            {"maxTotalBufferSize": 5 * 1024 * 1024,
                             "maxResourceBufferSize": 1024 * 1024},
                            session=self.page_id)
            except CdpError as exc:
                # 采不到接口是"少了一条线索"，不是导航失败——照常继续。
                self.harvest = None
                self._exc.append("network.enable 失败：%s" % exc)

        # 凭证要在导航之前进浏览器，否则第一跳就已经是登录页了。
        self._apply_identity(req.identity, "%s://%s:%d" % (scheme, host, port))
        try:
            self.s.call("Page.navigate", {"url": nav_url}, session=self.page_id, timeout=25)
        except CdpError as exc:
            return NavResult("error", "navigate 失败：%s" % exc, final_url=nav_url,
                             denied_urls=list(self.denied))

        self._settle(req.settle_s, req.wait_for)
        dom = self._dom_html()
        if dom is None:
            return NavResult("error", "取不到 DOM", final_url=nav_url, denied_urls=list(self.denied))

        final_url = self._evaluate("location.href", default=nav_url)
        window_name = self._evaluate("window.name", default="") or ""
        shot_sha = ""
        if req.screenshot:
            shot_sha = self._screenshot_sha()

        harvested: List[str] = []
        harvest_calls: List[Dict[str, Any]] = []
        if self.harvest is not None:
            harvested, harvest_calls = self._collect_harvest(
                req, scheme, host, port, level)

        dom_bytes = dom.encode("utf-8")
        body_bytes = dom_bytes
        body_sha = sha256_hex(body_bytes)
        headers = (
            Header("X-Pta-Capture", "literal", value="dom-snapshot"),
            Header("X-Pta-Browser", "literal", value=self.product[:40]),
            Header("X-Pta-Requests", "literal", value=str(self.allowed_count)),
            Header("X-Pta-Denied", "literal", value=str(len(self.denied))),
            Header("X-Pta-Nonce", "literal", value=nonce),
            Header("X-Pta-Window-Name", "literal", value=str(window_name)[:200]),
            Header("X-Pta-Console", "literal", value=json.dumps(
                {"console": self._console[:20], "exceptions": self._exc[:10]},
                ensure_ascii=False)[:2000]),
        )
        if shot_sha:
            headers += (Header("X-Pta-Screenshot-Sha", "literal", value=shot_sha),)

        canonical = CanonicalRequest(
            engagement_id=self.scope.engagement_id, method="GET", scheme=scheme, host=host,
            port=port, raw_path=raw_path, query=tuple(query), headers=headers, body=Body(),
            identity=req.identity, asset_node_id=req.asset_node_id,
            param_path=req.param_path, payload_class=req.payload_class,
            payload_variant=req.payload_variant, side_effect_level=level,
        )
        req_json = canonical.to_json()
        req_blob = self.cas.put(json.dumps(req_json, sort_keys=True).encode("utf-8"), kind="request")
        body_blob = self.cas.put(body_bytes, kind="response")
        ev_id = compute_evidence_id(req_json, body_sha, req.label)
        elapsed = int((time.time() - started) * 1000)
        ev = Evidence(
            evidence_id=ev_id, engagement_id=self.scope.engagement_id, label=req.label,
            identity=req.identity, request=canonical, request_blob=req_blob,
            status=200, content_type="text/html; dom-snapshot", body_sha256=body_sha,
            body_len=len(body_bytes), headers=tuple((h.name, h.value or "") for h in headers),
            sample_count=1, timings_ms=(elapsed,), ts_first=_now(), ts_last=_now(),
        )
        self.store.upsert_evidence(ev)
        self.store.log_action(engagement_id=self.scope.engagement_id, tool="browser_nav",
                              host=host, url=nav_url, decision="ok", reason="dom_snapshot",
                              level=level, approval_fp="",
                              detail={"evidence_id": ev_id, "requests": self.allowed_count,
                                      "denied": len(self.denied), "elapsed_ms": elapsed})
        return NavResult("ok", "", evidence_id=ev_id, final_url=final_url, body_sha256=body_sha,
                         dom_sha256=sha256_hex(dom_bytes), console=list(self._console),
                         denied_urls=list(self.denied), requests_allowed=self.allowed_count,
                         elapsed_ms=elapsed, harvested=harvested,
                         harvest_calls=harvest_calls)

    # ---------- 接口采集 ----------
    def _collect_harvest(self, req: NavRequest, scheme: str, host: str, port: int,
                         level: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """把页面自己发的调用逐条落成证据（label=harvest）。

        每条证据的 query **只留参数名不留值**：值里可能是会话 token 或手机号，
        我们需要的只是"这个接口有哪几个参数"。
        """
        calls = self.harvest.calls() if self.harvest is not None else []
        want = {c.request_id for c in self.harvest.body_requests(calls)} if self.harvest else set()
        ids: List[str] = []
        metas: List[Dict[str, Any]] = []
        for call in calls:
            body = b""
            if call.request_id in want:
                try:
                    res = self.s.call("Network.getResponseBody",
                                      {"requestId": call.request_id}, session=self.page_id,
                                      timeout=5)
                    body = decode_body(res) or b""
                except CdpError as exc:
                    call.error = "getResponseBody:%s" % str(exc)[:80]
            if len(body) > 2 * 1024 * 1024:
                body = body[:2 * 1024 * 1024]
                call.error = call.error or "body_truncated"
            c_scheme, c_host, c_port, c_path = call.parts()
            names = call.query_names()
            fields = call.body_fields()
            post = (call.post_data or "").encode("utf-8")
            req_body = Body()
            if post:
                kind = "json" if (call.post_data or "").strip()[:1] in ("{", "[") else "form"
                req_body = Body(kind=kind, sha256=sha256_hex(post),
                                blob=self.cas.put(post, kind="request_body"),
                                length=len(post))
            headers = (
                Header("X-Pta-Harvest", "literal", value="cdp-network"),
                Header("X-Pta-Resource", "literal", value=call.resource_type),
                Header("X-Pta-Status", "literal", value=str(call.status)),
                Header("X-Pta-Query-Names", "literal", value=",".join(names)[:300]),
                Header("X-Pta-Body-Fields", "literal", value=",".join(fields)[:300]),
            )
            if call.mime:
                headers += (Header("Content-Type", "literal", value=call.mime[:120]),)
            canonical = CanonicalRequest(
                engagement_id=self.scope.engagement_id, method=call.method,
                scheme=c_scheme, host=c_host, port=c_port, raw_path=c_path,
                query=tuple((n, "") for n in names), headers=headers, body=req_body,
                identity=req.identity, asset_node_id=req.asset_node_id,
                side_effect_level="L1",
            )
            req_json = canonical.to_json()
            req_blob = self.cas.put(json.dumps(req_json, sort_keys=True).encode("utf-8"),
                                    kind="request")
            body_sha = sha256_hex(body)
            body_blob = self.cas.put(body, kind="response") if body else ""
            ev_id = compute_evidence_id(req_json, body_sha, "harvest")
            self.store.upsert_evidence(Evidence(
                evidence_id=ev_id, engagement_id=self.scope.engagement_id, label="harvest",
                identity=req.identity, request=canonical, request_blob=req_blob,
                status=call.status or 0, content_type=call.mime or "application/octet-stream",
                body_sha256=body_blob, body_len=len(body),
                headers=tuple((h.name, h.value or "") for h in headers),
                sample_count=1, timings_ms=(0,), ts_first=_now(), ts_last=_now(),
            ))
            ids.append(ev_id)
            meta = call.to_json()
            meta["evidence_id"] = ev_id
            meta["body_len"] = len(body)
            meta["has_response_body"] = bool(body)
            metas.append(meta)
        if ids:
            self.store.log_action(
                engagement_id=self.scope.engagement_id, tool="browser_harvest",
                host=host, url=req.url, decision="ok",
                reason="harvested:%d" % len(ids), level=level, approval_fp="",
                detail={"evidence_ids": ids, "stats": self.harvest.stats()})
        return ids, metas

    # ---------- 小工具 ----------
    def _settle(self, settle_s: float, wait_for: Optional[str]) -> None:
        deadline = time.time() + max(settle_s, 0.2)
        while time.time() < deadline:
            try:
                self.s.pump(time.time() + 0.2)
            except CdpError:
                break
        if wait_for:
            give_up = time.time() + 5.0
            while time.time() < give_up:
                if self._evaluate("Boolean(%s)" % wait_for, default=False):
                    return
                time.sleep(0.1)

    def _evaluate(self, expr: str, default: Any = None) -> Any:
        try:
            res = self.s.call("Runtime.evaluate",
                              {"expression": expr, "returnByValue": True, "awaitPromise": True},
                              session=self.page_id, timeout=10)
        except CdpError:
            return default
        if "exceptionDetails" in res:
            return default
        return (res.get("result") or {}).get("value", default)

    def _dom_html(self) -> Optional[str]:
        val = self._evaluate("document.documentElement ? document.documentElement.outerHTML : null")
        return val if isinstance(val, str) else None

    def _screenshot_sha(self) -> str:
        try:
            res = self.s.call("Page.captureScreenshot", {"format": "png"},
                              session=self.page_id, timeout=15)
        except CdpError:
            return ""
        import base64
        data = base64.b64decode(res.get("data", ""))
        if not data:
            return ""
        return self.cas.put(data, kind="screenshot")


def open_page(browser: "BrowserProcess", scope: Scope, store: Any, cas: Any, budget: Any,
              dns: Optional[DnsPin] = None, bus: Any = None,
              vault: Any = None) -> BrowserTool:
    """在一个已启动的浏览器里开一个 page target，返回带范围校验的工具。"""
    if browser.session is None:
        raise CdpError("浏览器尚未启动")
    tid = browser.session.call("Target.createTarget", {"url": "about:blank"})["targetId"]
    sid = browser.session.call("Target.attachToTarget",
                               {"targetId": tid, "flatten": True})["sessionId"]
    return BrowserTool(scope, store, cas, budget, browser.session, sid, tid,
                       product=browser.product, dns=dns, bus=bus, vault=vault)


def close_page(tool: BrowserTool) -> None:
    try:
        tool.s.call("Target.closeTarget", {"targetId": tool.target_id}, timeout=5)
    except Exception:            # 连接可能已经断了；清理路径上不该再抛
        pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def resolver_rules(scope: Scope, dns: Optional[DnsPin] = None) -> Tuple[str, ...]:
    """把授权域钉到我们解析出的 IP：浏览器自己解析不出第二个地址。"""
    pin = dns or DnsPin()
    rules = []
    for domain in scope.domains:
        if domain.startswith("*."):
            continue
        try:
            ip = pin.pin(domain, scope)
        except Exception:
            continue
        rules.append("MAP %s %s" % (domain, ip))
    if not rules:
        return ()
    return ("--host-resolver-rules=" + ",".join(rules),)
