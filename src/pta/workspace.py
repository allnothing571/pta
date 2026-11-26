"""工作区装配：一个 engagement 目录 = 一套 scope + store + cas + vault。

目录布局：
  <root>/scope.json
  <root>/index.sqlite
  <root>/cas/{bodies,manifest.jsonl}
  <root>/vault.json
  <root>/logs/
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .approvals import ApprovalGate
from .budget import Budget
from .cas import Cas, default_cipher
from .events import Bus
from .probe import ProbeTool
from .oob import OobCollector
from .replay import Replayer
from .scope import DnsPin, Scope
from .store import Store
from .transport import DirectPinnedTransport, MockTransport, ProxyTransport, Transport, parse_proxy
from .vault import Vault


@dataclass
class Workspace:
    root: str
    scope: Scope
    store: Store
    cas: Cas
    vault: Vault
    budget: Budget
    gate: ApprovalGate
    transport: Transport
    probe: ProbeTool
    replayer: Replayer
    bus: Bus = None
    oob: Optional["OobCollector"] = None
    browser: Optional[Any] = None        # BrowserTool（browser_nav 模板需要）
    browser_proc: Optional[Any] = None   # BrowserProcess，负责关闭


def scope_from_dict(d: Dict[str, Any]) -> Scope:
    return Scope(
        engagement_id=d["engagement_id"],
        domains=tuple(d.get("domains", ())),
        cidrs=tuple(d.get("cidrs", ())),
        deny_paths=tuple(d.get("deny_paths", ())),
        allow_private=bool(d.get("allow_private", False)),
        rate_per_host=float(d.get("rate_per_host", 5.0)),
        max_requests=int(d.get("max_requests", 9000)),
        expires_at=d.get("expires_at"),
        egress_proxy=d.get("egress_proxy"),
        signed_by=d.get("signed_by", "local-operator"),
        allowed_ports=tuple(int(p) for p in d.get("allowed_ports", (80, 443))),
    )


def build_transport(scope: Scope) -> Transport:
    if scope.egress_proxy:
        host, port = parse_proxy(scope.egress_proxy)
        return ProxyTransport(host, port, tls_verify=not scope.allow_private)
    return DirectPinnedTransport(tls_verify=not scope.allow_private)


def open_workspace(root: str, transport: Optional[Transport] = None,
                   dns: Optional[DnsPin] = None,
                   oob: Optional["OobCollector"] = None,
                   browser: Optional[Any] = None,
                   browser_proc: Optional[Any] = None) -> Workspace:
    root = os.path.abspath(root)
    scope_path = os.path.join(root, "scope.json")
    if not os.path.exists(scope_path):
        raise FileNotFoundError("缺少 %s，先跑 pta init" % scope_path)
    with open(scope_path, "r", encoding="utf-8") as fh:
        scope = scope_from_dict(json.load(fh))

    os.makedirs(os.path.join(root, "logs"), exist_ok=True)
    store = Store(os.path.join(root, "index.sqlite"))
    # 登记这一轮：报告要能列出"库里有哪几轮"，靠的就是这张表。
    # 以前只在 CLI 手动 put_engagement，绕过 CLI 建的工作区在 engage 表里是空的。
    store.put_engagement(scope.engagement_id, scope_payload(scope),
                         scope.signed_by or "operator")
    cas = Cas(os.path.join(root, "cas"), cipher=default_cipher(os.path.join(root, ".master.key")))
    vault = Vault(os.path.join(root, "vault.json"))
    budget = Budget(max_requests=scope.max_requests, rate_per_host=scope.rate_per_host)
    # 重开工作区不等于预算清零：账本在 action_log 里，PTT 在 ptt_node 里。
    # 这两样都不是内存态，断点续跑靠的就是它们。
    budget.restore(store.count_sent(scope.engagement_id),
                   store.sent_by_host(scope.engagement_id))
    gate = ApprovalGate(store)
    dns = dns or DnsPin()
    bus = Bus()

    tx = transport
    if tx is None:
        tx = build_transport(scope)

    probe = ProbeTool(scope=scope, store=store, cas=cas, transport=tx, gate=gate,
                      budget=budget, vault=vault, dns=dns, bus=bus, oob=oob)
    replayer = Replayer(scope=scope, store=store, cas=cas, transport=tx, vault=vault, dns=dns)
    return Workspace(root=root, scope=scope, store=store, cas=cas, vault=vault, budget=budget,
                     gate=gate, transport=tx, probe=probe, replayer=replayer, bus=bus, oob=oob,
                     browser=browser, browser_proc=browser_proc)


def attach_browser(ws: Workspace, cfg: Optional[Any] = None,
                   dns: Optional[DnsPin] = None) -> Any:
    """给工作区挂一个真浏览器（browser_nav 模板用）。调用方负责 close_browser。

    域名解析用 --host-resolver-rules 钉死（等价 DNS pin），网络出口仍然受
    Fetch 拦截器逐条校验——两条独立的闸门。
    """
    from .browser import BrowserConfig, BrowserProcess, open_page, resolver_rules

    if ws.browser is not None:
        return ws.browser
    cfg = cfg or BrowserConfig()
    rules = resolver_rules(ws.scope, dns=dns or DnsPin())
    if rules:
        cfg = BrowserConfig(**{**cfg.__dict__, "extra_args": tuple(cfg.extra_args) + rules})
    proc = BrowserProcess(cfg)
    proc.start()
    tool = open_page(proc, ws.scope, ws.store, ws.cas, ws.budget, dns=dns, bus=ws.bus,
                     vault=ws.vault)
    ws.browser = tool
    ws.browser_proc = proc
    return tool


def close_browser(ws: Workspace) -> None:
    from .browser import close_page

    if ws.browser is not None:
        try:
            close_page(ws.browser)
        finally:
            ws.browser = None
    if ws.browser_proc is not None:
        try:
            ws.browser_proc.stop()
        finally:
            ws.browser_proc = None


def scope_payload(scope: Scope) -> Dict[str, Any]:
    return {
        "engagement_id": scope.engagement_id,
        "domains": list(scope.domains),
        "cidrs": list(scope.cidrs),
        "deny_paths": list(scope.deny_paths),
        "allow_private": scope.allow_private,
        "rate_per_host": scope.rate_per_host,
        "max_requests": scope.max_requests,
        "expires_at": scope.expires_at,
        "egress_proxy": scope.egress_proxy,
        "signed_by": scope.signed_by,
        "allowed_ports": list(scope.allowed_ports),
    }


def init_workspace(root: str, scope: Scope) -> str:
    os.makedirs(root, exist_ok=True)
    payload = scope_payload(scope)
    path = os.path.join(root, "scope.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path
