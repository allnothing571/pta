# -*- coding: utf-8 -*-
"""把浏览器里的登录态搬进工作区。

真实目标的第一道坎不是漏洞判定，是"我这条请求是登录着的"。在 devtools 里
Network → 右键 → Copy as cURL，粘进来，就得到了一组带着 Cookie / Authorization /
CSRF token 的请求头。这里负责把这坨文本变成 `identity` 能用的东西。

三条取舍：

1. **只留身份相关的头**。UA / Accept / Sec-Fetch-* 这些是浏览器的指纹，工具自己有一套
   （通道消歧会换），留着反而会和通道实验打架；Host / Content-Length 更不能留，它们由
   每次请求的 URL 和 body 决定。
2. **值不打印**。`auth ls` 只显示头名和掩码后的前缀——凭证仓本来就是明文 JSON，
   再往终端上打一遍只会进 shell 历史。
3. **Cookie 整条存**。拆成多个 Set-Cookie 再拼回去没有意义，服务端也只看拼好的那条。
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# 这些头由每次请求的 URL/body 决定，或者本来就是浏览器指纹，导入时必须丢掉。
_DROP_EXACT = frozenset({
    "host", "content-length", "content-type", "connection", "accept", "accept-encoding",
    "accept-language", "user-agent", "cache-control", "pragma", "dnt", "te", "upgrade-insecure-requests",
    "expect", "transfer-encoding", "keep-alive", "if-none-match", "if-modified-since",
})

# 前缀丢弃：Sec-Fetch-* / Sec-Ch-Ua-* / :authority 这类伪头
_DROP_PREFIX = ("sec-", "sec-ch-", ":")

# 身份相关：只要命中这些就保留（不看是否在白名单外）
_KEEP_PATTERNS = (
    re.compile(r"^authorization$"),
    re.compile(r"^cookie$"),
    re.compile(r"^x-"),
    re.compile(r"csrf", re.I),
    re.compile(r"token", re.I),
    re.compile(r"api[-_]?key", re.I),
    re.compile(r"auth", re.I),
    re.compile(r"^referer$"),
    re.compile(r"^origin$"),
)

_IDENTITY_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


class CredentialError(ValueError):
    pass


@dataclass(frozen=True)
class Imported:
    """从 cURL / 手写头里解析出来的东西。"""
    method: str = "GET"
    url: str = ""
    headers: Tuple[Tuple[str, str], ...] = ()
    dropped: Tuple[str, ...] = ()
    cookie: str = ""

    def to_json(self) -> Dict[str, object]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": [{"name": k, "value": mask(v)} for k, v in self.headers],
            "dropped": list(self.dropped),
            "cookie_len": len(self.cookie),
        }


def mask(value: str) -> str:
    """凭证只露头尾，中间打码。"""
    if len(value) <= 10:
        return "*" * len(value)
    return "%s…%s（%d 字节）" % (value[:6], value[-2:], len(value))


def check_identity(name: str) -> str:
    if not _IDENTITY_RE.match(name or ""):
        raise CredentialError("身份名只能用字母、数字、下划线、点和短横线：%r" % (name,))
    return name


def _split_header(line: str) -> Tuple[str, str]:
    if ":" not in line:
        raise CredentialError("请求头要写成 `Name: value`：%r" % (line,))
    name, value = line.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name:
        raise CredentialError("请求头缺少名字：%r" % (line,))
    return name, value


def _tokenize(text: str) -> List[str]:
    """先按 bash 规则切；失败再按 Windows 的 `^` 续行 + 双引号切。"""
    flat = re.sub(r"\\\r?\n", " ", text)
    flat = re.sub(r"\^\r?\n", " ", flat)
    flat = flat.strip()
    if flat.startswith("$"):
        flat = flat[1:].strip()
    try:
        parts = shlex.split(flat, posix=True)
    except ValueError:
        # `Copy as cURL (cmd)`：双引号不转义，按空白切再剥引号
        parts = [p.strip('"').strip("'") for p in flat.split()]
    if parts and parts[0].lower() in ("curl", "curl.exe"):
        parts = parts[1:]
    return parts


def parse_curl(text: str, drop_extra: Tuple[str, ...] = (), keep_all: bool = False) -> Imported:
    """解析 `Copy as cURL` 的文本。只认 GET/POST 这类方法、URL、-H、-b、--data。"""
    if not text or not text.strip():
        raise CredentialError("没有内容可解析")
    parts = _tokenize(text)
    method = ""
    url = ""
    raw_headers: List[Tuple[str, str]] = []
    cookies: List[str] = []
    i = 0
    while i < len(parts):
        tok = parts[i]
        if tok in ("-H", "--header") and i + 1 < len(parts):
            raw_headers.append(_split_header(parts[i + 1]))
            i += 2
        elif tok in ("-b", "--cookie") and i + 1 < len(parts):
            cookies.append(parts[i + 1])
            i += 2
        elif tok in ("-X", "--request") and i + 1 < len(parts):
            method = parts[i + 1].upper()
            i += 2
        elif tok in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii") and i + 1 < len(parts):
            if not method:
                method = "POST"
            i += 2
        elif tok in ("--url",) and i + 1 < len(parts):
            url = parts[i + 1]
            i += 2
        elif tok.startswith("-"):
            # --compressed / -k / --insecure 这类开关不取值
            i += 1
        else:
            if not url:
                url = tok
            i += 1
    if not url:
        raise CredentialError("没找到 URL：cURL 里应该有一个 http(s) 地址")
    if not re.match(r"^https?://", url, re.I):
        raise CredentialError("只接受 http/https 的 URL：%r" % (url,))

    kept, dropped = [], []
    drop_set = {d.lower() for d in drop_extra}
    for name, value in raw_headers:
        low = name.lower()
        if low in drop_set:
            dropped.append(name)
            continue
        if not keep_all and (low in _DROP_EXACT or low.startswith(_DROP_PREFIX)):
            dropped.append(name)
            continue
        if not keep_all and not any(p.search(low) for p in _KEEP_PATTERNS):
            dropped.append(name)
            continue
        kept.append((name, value))

    cookie = "; ".join(c for c in cookies if c)
    if cookie:
        existed = [k for k, _ in kept if k.lower() == "cookie"]
        if existed:
            cookie = "; ".join([v for k, v in kept if k.lower() == "cookie"] + [cookie])
            kept = [(k, v) for k, v in kept if k.lower() != "cookie"]
        kept.append(("Cookie", cookie))
    return Imported(method=method or "GET", url=url,
                    headers=tuple(kept), dropped=tuple(dropped), cookie=cookie)


def parse_header_lines(lines: List[str], keep_all: bool = True) -> Tuple[Tuple[str, str], ...]:
    """`--header "Name: value"` 的多行输入。"""
    out = []
    for line in lines:
        if not line or not line.strip():
            continue
        out.append(_split_header(line))
    return tuple(out)


def parse_cookie_file(text: str) -> str:
    """Netscape cookies.txt（7 列，tab 分隔）或 `k=v; k2=v2` 两种都吃。"""
    pairs: List[str] = []
    netscape = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") and not line.startswith("#HttpOnly_"):
            continue
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
        cols = line.split("\t")
        if len(cols) >= 7:
            netscape = True
            pairs.append("%s=%s" % (cols[5].strip(), cols[6].strip()))
            continue
        for chunk in line.split(";"):
            chunk = chunk.strip()
            if "=" in chunk:
                pairs.append(chunk)
    if not pairs:
        return ""
    # 后出现的同名 cookie 覆盖前面的（浏览器就是这么做的）
    seen: Dict[str, str] = {}
    for pair in pairs:
        k, _, v = pair.partition("=")
        if k.strip():
            seen[k.strip()] = v.strip()
    return "; ".join("%s=%s" % (k, v) for k, v in seen.items())


def merge_headers(*groups: Tuple[Tuple[str, str], ...]) -> Tuple[Tuple[str, str], ...]:
    """后面的覆盖前面的（同名不分大小写），顺序按第一次出现的位置。"""
    order: List[str] = []
    values: Dict[str, Tuple[str, str]] = {}
    for group in groups:
        for name, value in group:
            low = name.lower()
            if low not in values:
                order.append(low)
            values[low] = (name, value)
    return tuple(values[low] for low in order)


def read_text(path: Optional[str]) -> str:
    """`-` 或空表示 stdin。"""
    if not path or path == "-":
        return __import__("sys").stdin.read()
    with open(os.path.expanduser(path), "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()
