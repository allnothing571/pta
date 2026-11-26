"""Scope Kernel：范围判定 + DNS pin。

判定顺序固定，任何一步失败都抛 ScopeViolation / DnsPinViolation，
由调用方写成 denied 记录。这里不发请求，只做判定。
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .errors import DnsPinViolation, ScopeViolation


def _norm_host(host: str) -> str:
    h = host.encode("idna").decode("ascii").lower().rstrip(".")
    return h


@dataclass(frozen=True)
class Scope:
    engagement_id: str
    domains: Tuple[str, ...] = ()          # "example.com" 精确；"*.example.com" 通配一级
    cidrs: Tuple[str, ...] = ()            # 可选：要求解析结果落在这些网段
    deny_paths: Tuple[str, ...] = ("/logout", "/delete", "/admin/bulk", "/account/close")
    allow_private: bool = False            # 仅本地靶场置 True
    rate_per_host: float = 5.0             # req/s
    max_requests: int = 9000
    expires_at: Optional[str] = None
    egress_proxy: Optional[str] = None     # "127.0.0.1:8080"，设置后禁止直连
    signed_by: str = "local-operator"
    allowed_ports: Tuple[int, ...] = (80, 443)   # 本地靶场显式加端口，默认只放 80/443

    # ---------- 域名 ----------
    def domain_allowed(self, host: str) -> bool:
        try:
            h = _norm_host(host)
        except UnicodeError:
            return False
        for pat in self.domains:
            p = pat.lower().strip()
            if p.startswith("*."):
                suffix = p[2:]
                if h.endswith("." + suffix) and h != suffix:
                    return True
            elif h == p:
                return True
        return False

    def path_denied(self, raw_path: str) -> bool:
        low = (raw_path or "/").lower()
        return any(d.lower() in low for d in self.deny_paths)

    def ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if not addr.is_global and not self.allow_private:
            return False
        if self.cidrs:
            nets = [ipaddress.ip_network(c, strict=False) for c in self.cidrs]
            return any(addr in n for n in nets)
        return True

    def expired(self, now: Optional[datetime] = None) -> bool:
        if not self.expires_at:
            return False
        now = now or datetime.utcnow()
        try:
            return datetime.fromisoformat(self.expires_at) < now
        except ValueError:
            return True

    def check_url(self, url: str) -> Tuple[str, str, int, str]:
        """返回 (host, scheme, port, raw_path)；越界抛 ScopeViolation。"""
        if len(url) > 2048:
            raise ScopeViolation("URL 长度不合法")
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ScopeViolation("只允许 http/https")
        if parsed.username or parsed.password:
            raise ScopeViolation("URL 不允许内嵌凭据")
        host = parsed.hostname or ""
        if not host:
            raise ScopeViolation("URL 缺少主机名")
        if not self.domain_allowed(host):
            raise ScopeViolation("主机不在授权域名白名单：%s" % host)
        if self.path_denied(parsed.path):
            raise ScopeViolation("路径在 deny_paths 中：%s" % parsed.path)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port not in self.allowed_ports:
            raise ScopeViolation("端口 %d 不在允许范围 %s" % (port, list(self.allowed_ports)))
        return _norm_host(host), parsed.scheme.lower(), port, parsed.path or "/"


Resolver = Callable[[str], Sequence[str]]


def system_resolver(host: str) -> Sequence[str]:
    infos = socket.getaddrinfo(host, None)
    out: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


@dataclass
class DnsPin:
    """解析一次、校验、随后只连接 pin 住的地址。

    真实漏洞：只在解析时校验、连接时重新解析 = TOCTOU。这里把 IP 交给 transport，
    transport 只允许连这个 IP。
    """

    resolver: Resolver = system_resolver
    cache: dict = field(default_factory=dict)

    def pin(self, host: str, scope: Scope) -> str:
        if host in self.cache:
            ips = self.cache[host]
        else:
            try:
                ips = list(self.resolver(host))
            except Exception as exc:
                raise DnsPinViolation("解析失败：%s" % exc)
            self.cache[host] = ips
        if not ips:
            raise DnsPinViolation("解析结果为空：%s" % host)
        for ip in ips:
            if not scope.ip_allowed(ip):
                raise DnsPinViolation("解析结果越界：%s -> %s" % (host, ip))
        return ips[0]


def check_request(scope: Scope, method: str, url: str, level: str = "L1") -> Tuple[str, str, int, str]:
    if scope.expired():
        raise ScopeViolation("授权已过期")
    if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        raise ScopeViolation("方法不合法：%s" % method)
    if level == "L3":
        raise ScopeViolation("L3 动作在 P0 编译期禁用")
    return scope.check_url(url)
