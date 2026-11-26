"""资源邻接图：把"看到的资产"连成一张小图，再从图上展开候选。

为什么需要：以前 Planner 只看单个资产（这个 URL 有哪些参数、用了什么方法），
看不见资产之间的关系。但"GET /api/users/7 用 A 的身份读到了 200"这件事本身
就有两个推论：

- 同一个资源换个方法（PUT / PATCH）可能也能写 —— `same_resource`
- 同一个模板换个 id（/api/users/8）可能也能读 —— `sibling_object`

这不是猜漏洞，是把已有证据外推一步。所以图候选的优先级刻意压得很低
（0.42~0.62），只在前面的规则候选排不满时才补位：规则命中的证据更硬。

五条边，只做能在离线证据上验证的：

| 边 | 判据 | 展开成 |
|---|---|---|
| `same_resource` | 归一化路径相同、方法不同 | 换方法试写（idor-write-object） |
| `sibling_object` | 归一化路径相同、方法相同、id 不同 | 邻近对象试读（idor-object-ref） |
| `child_resource` | A 的路径是 B 的前缀 | 集合资源下的单个对象 |
| `refers_to` | 响应体里有 `xxx_id: 7`，站点上存在对应资源模板 | 直读被引用的对象 |
| `param_ref` | URL 查询里有 `xxx_id=7`（**只有 harvest 才带真值**） | 直读那个对象 |

后两条是"跨对象"外推，判据都要求**站点上确实存在一个能吃这个 id 的资源模板**
（`/api/users/{id}`），否则宁可不连：凭空造一个 URL 出来，打出去只有 404。

`refers_to` 要读响应体重新解析，"7 这个数字是对谁的引用"只能靠字段名猜，
所以它排在最后（0.42）。`param_ref` 稍高（0.46）：`?user_id=7` 里的 7 是页面
自己发出去的真值，这个对象一定存在，只是"它是否归我"还不知道。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit, urlunsplit

# 路径里看起来像对象 id 的一段：纯数字，或 uuid，或 24 位十六进制（Mongo ObjectId）
_ID_SEGMENT = re.compile(r"^(?:\d{1,12}|[0-9a-f]{24}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
                         r"-[0-9a-f]{4}-[0-9a-f]{12})$", re.I)
# 值是 id 的查询参数名
_ID_PARAM = re.compile(r"^(?:id|ids|uid|user_?id|order_?id|account_?id|item_?id|"
                       r"product_?id|pid|oid|nid|sid)$", re.I)

# ---------- refers_to：响应体里"这个对象引用了谁" ----------

# 长得像对象引用的字段名：`xxx_id`。裸 `id` 不算——那是这个对象自己的标识，
# 不是对别人的引用。
_REF_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9]*_id$")
# 同样是 `*_id` 但指向的不是业务对象的：跟踪号、会话号、消息号……
# 把它们当引用会连出一堆不存在的资源。
_REF_NOISE = frozenset({
    "request_id", "trace_id", "traceparent_id", "correlation_id", "session_id",
    "message_id", "event_id", "task_id", "job_id", "transaction_id", "nonce_id",
    "batch_id", "run_id", "span_id", "parent_span_id", "click_id", "visit_id",
    "device_id", "installation_id", "version_id", "revision_id",
})
# 字段词干 → 资源段词干。`owner_id` 指向的通常是 /api/users/{id}，
# 靠字面匹配（owner ≠ users）是连不上的，这里把常见同义词归并。
_REF_ALIASES = {
    "owner": "user", "author": "user", "creator": "user", "assignee": "user",
    "reporter": "user", "buyer": "user", "seller": "user", "member": "user",
    "sender": "user", "receiver": "user", "manager": "user", "employee": "user",
    "requester": "user", "approver": "user", "contact": "user", "customer": "user",
    "org": "organization", "tenant": "organization", "company": "organization",
}

MAX_REF_BODY = 256 * 1024
MAX_REFS = 200
_MAX_REF_DEPTH = 6
# 一个 URL 上最多认几个"引用参数"。一屏列表请求常带四五个 `*_id`，
# 全展开会把候选池占满，取前几个就够（payload 里也是这几个最要紧）。
MAX_PARAM_REFS = 3
# 同一个源节点最多由 param_ref 贡献几条候选
MAX_PARAM_REF_CANDS = 2


def host_key(url: str) -> str:
    """比较用的主机键：域名小写、默认端口去掉。

    为什么需要：证据表里的 URL 一律带端口（`http://host:80/x`），浏览器
    （CDP）抓到的 URL 按页面实际写法来（`http://host/x`）。两种写法是同一台
    机器，不做归一的话"爬到的资产"和"页面自己发的资产"会被当成两个站，
    它们之间的边（换方法、换对象、父子）全断——而这两路本来就是同一批接口。
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:            # 端口写成非数字：原样保留，别在这里抛
        return parts.netloc.lower()
    if port is None:
        return host
    if (parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443):
        return host
    return "%s:%d" % (host, port)


def same_endpoint(a: str, b: str) -> bool:
    """两个 URL 是不是"同一个端点"（只差默认端口写法 / query 顺序）。"""
    pa, pb = urlsplit(a), urlsplit(b)
    if host_key(a) != host_key(b):
        return False
    if (pa.path.rstrip("/") or "/") != (pb.path.rstrip("/") or "/"):
        return False
    return (sorted(parse_qsl(pa.query, keep_blank_values=True))
            == sorted(parse_qsl(pb.query, keep_blank_values=True)))


def resource_key(url: str) -> str:
    """把一个 URL 归一成"资源模板"：`/api/users/7?tab=x` → `/api/users/{id}`。

    归一化只做三件事，每一件都要能反向还原（展开时用同一个模板换 id）：
    数字段 → `{id}`；id 类查询参数的值 → `{id}`；路径尾斜杠去掉。
    """
    parts = urlsplit(url)
    segs = [s for s in parts.path.split("/") if s]
    out: List[str] = []
    for i, seg in enumerate(segs):
        out.append("{id}" if _ID_SEGMENT.match(seg) and i > 0 else seg)
    query = []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        query.append((name, "{id}" if (_ID_PARAM.match(name) and value) else value))
    query.sort()
    path = "/" + "/".join(out)
    if parts.path.endswith("/") and path != "/":
        path += "/"
    return path + (("?" + "&".join("%s=%s" % kv for kv in query)) if query else "")


def _object_ids(url: str) -> List[Tuple[str, str]]:
    """把 URL 里"具体是哪个对象"的部分抽出来：路径段和 id 类查询参数。

    返回 `[("path", "7"), ("query", "42")]` 这样的列表。展开兄弟对象时，
    只换其中一个、其余保持不变——这才是"同一个资源、另一个对象"。
    """
    parts = urlsplit(url)
    segs = [s for s in parts.path.split("/") if s]
    out: List[Tuple[str, str]] = []
    for i, seg in enumerate(segs):
        if i > 0 and _ID_SEGMENT.match(seg):
            out.append(("seg:%d" % i, seg))
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if _ID_PARAM.match(name) and value:
            out.append(("query:%s" % name, value))
    return out


def replace_object_id(url: str, slot: str, value: str) -> str:
    """把 `slot` 那一处的对象 id 换成 `value`，其余部分逐字保留。"""
    parts = urlsplit(url)
    if slot.startswith("seg:"):
        idx = int(slot.split(":", 1)[1])
        raw = parts.path.split("/")
        # raw[0] 是空串（路径以 / 开头），所以段序号要 +1
        if idx + 1 < len(raw):
            raw[idx + 1] = value
            path = "/".join(raw)
        else:
            path = parts.path
        return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
    if slot.startswith("query:"):
        name = slot.split(":", 1)[1]
        pairs = [(n, value if n == name else v) for n, v in
                 parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           "&".join("%s=%s" % kv for kv in pairs), parts.fragment))
    return url


def _bump(value: str, step: int) -> Optional[str]:
    """数字 id 加减；非数字（uuid / ObjectId）不做相邻推导——那没有"下一个"的概念。"""
    if not value.isdigit():
        return None
    n = int(value) + step
    if n <= 0:
        return None
    return str(n)


# 一个几乎不可能真实存在的对象 id：用来做"负对照"。
# 如果读它也能拿到和正常对象一样的响应，说明服务端根本没按 id 查，
# 那么"两个身份读到同一份内容"就不再是越权的证据。
_DECOY_VALUE = "999999999"


def decoy_url(url: str) -> Optional[str]:
    """把 URL 里第一个对象槽换成不可能存在的值；没有对象槽返回 None。

    只在"确实有对象槽"时才有意义：`?id=7` 换成 `?id=999999999`，
    `/api/users/7` 换成 `/api/users/999999999`。
    """
    for slot, _value in _object_ids(url):
        return replace_object_id(url, slot, _DECOY_VALUE)
    return None


def sweep_urls(url: str, count: int = 20, step: int = 1) -> List[str]:
    """从第一个对象槽的当前值往后，连续取 `count` 个兄弟对象。

    只处理数字 id：`?id=7` → `?id=8`…；`/api/users/7` → `/api/users/8`…
    uuid 形态不能枚举（也没有"相邻"可言），返回空——扫不了就说扫不了，
    不要拿随机 uuid 去撞，那既不准也会把目标打出一堆 404 噪声。
    """
    if count <= 0:
        return []
    for slot, value in _object_ids(url):
        if not value.isdigit():
            return []
        base = int(value)
        return [replace_object_id(url, slot, str(base + step * (i + 1)))
                for i in range(count)]
    return []


def _ref_value(value: object) -> Optional[str]:
    """引用值必须能直接拼进 URL：数字或 uuid/ObjectId 形态的字符串。

    嵌套对象（`"user": {"id": 3}`）不在这里处理——字段名已经不叫 `*_id` 了，
    靠结构猜"这个对象是不是引用"是另一件事，误报率更高。
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return str(value) if value >= 0 else None
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            return s
        if _ID_SEGMENT.match(s):
            return s
    return None


def _walk_refs(node: object, path: str, out: List[Tuple[str, str, str]], depth: int) -> None:
    if len(out) >= MAX_REFS or depth > _MAX_REF_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            here = ("%s.%s" % (path, key)) if path else str(key)
            name = str(key)
            if _REF_FIELD.match(name) and name.lower() not in _REF_NOISE:
                raw = _ref_value(value)
                if raw is not None:
                    stem = name[:-3].lower()          # 去掉 "_id"
                    out.append((here, stem, raw))
                    if len(out) >= MAX_REFS:
                        return
            _walk_refs(value, here, out, depth + 1)
    elif isinstance(node, list):
        for i, item in enumerate(node[:20]):
            _walk_refs(item, "%s[%d]" % (path, i), out, depth + 1)


def extract_refs(body: bytes, content_type: Optional[str] = None) -> List[Tuple[str, str, str]]:
    """从响应体里抽"这个对象引用了哪个 id"。返回 `[(字段路径, 词干, id 值)]`。

    只在确定是 JSON 时解析：HTML 里一行 `data-user-id="3"` 也想当引用的话，
    误报会比图上的其他三类边高一个量级，不做。
    """
    if not body or len(body) > MAX_REF_BODY:
        return []
    ctype = (content_type or "").lower()
    head = body.lstrip()[:1]
    if head not in (b"{", b"["):
        return []
    if ctype and "json" not in ctype and "javascript" not in ctype:
        return []
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return []
    out: List[Tuple[str, str, str]] = []
    _walk_refs(data, "", out, 0)
    return out


def param_refs(url: str) -> List[Tuple[str, str, str]]:
    """从 URL 的查询参数里抽"它引用了哪个对象"：`?user_id=7` → `("user_id", "user", "7")`。

    为什么单独一条：响应体那条（`extract_refs`）要等响应回来且是 JSON，
    而查询参数是我们**发请求之前**就写着的东西——只要 URL 带真值就有。

    而 URL 带真值这件事，目前只有 harvest 做得到：证据表里我们自己发的请求
    query 值一律留空（值可能是会话 token）。所以这条路在"走浏览器抓一次"之后
    才有货，没走浏览器时它自然为空，不需要额外开关。

    三条克制：
    - 只认 `xxx_id` 这种名字。裸 `id` 是"这个对象自己"，不是引用；
    - 噪声表里的（`request_id`/`session_id`…）不认；
    - 值必须是数字 / uuid / ObjectId，否则拼不进 URL。
    """
    out: List[Tuple[str, str, str]] = []
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if not value or not _REF_FIELD.match(name):
            continue
        low = name.lower()
        if low in _REF_NOISE:
            continue
        raw = _ref_value(value)
        if raw is None:
            continue
        out.append((name, low[:-3], raw))         # 去掉 "_id" 得到词干
        if len(out) >= MAX_PARAM_REFS:
            break
    return out


def _resource_stems(resource: str) -> List[str]:
    """`/api/users/{id}` → ["users", "user"]：能接受引用的资源名。"""
    segs = [s for s in resource.split("?", 1)[0].split("/") if s]
    # 最后一个 {id} 前面那一段才是资源名
    if segs and segs[-1] == "{id}":
        segs = segs[:-1]
    if not segs:
        return []
    last = segs[-1].lower()
    out = [last]
    if last.endswith("ies"):
        out.append(last[:-3] + "y")
    elif last.endswith("es") and not last.endswith("ses"):
        out.append(last[:-2])
    elif last.endswith("s"):
        out.append(last[:-1])
    return out


@dataclass(frozen=True)
class Node:
    key: str                # "GET /api/users/{id}"
    url: str
    method: str
    resource: str
    identity: str = "none"
    status: int = 0

    def to_json(self) -> Dict[str, object]:
        return {"key": self.key, "url": self.url, "method": self.method,
                "resource": self.resource, "status": self.status,
                "identity": self.identity}


@dataclass(frozen=True)
class Edge:
    kind: str               # same_resource | sibling_object | child_resource | refers_to
    src: str                # Node.key
    dst: str
    reason: str
    dst_url: str = ""       # refers_to 专用：目标还没成为节点，URL 直接挂在边上
    dst_method: str = "GET"

    def to_json(self) -> Dict[str, str]:
        out = {"kind": self.kind, "src": self.src, "dst": self.dst, "reason": self.reason}
        if self.dst_url:
            out["dst_url"] = self.dst_url
        return out


@dataclass
class Graph:
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)

    def add(self, node: Node) -> None:
        self.nodes.setdefault(node.key, node)

    def link(self, edge: Edge) -> None:
        # 同一条边不重复记：A→B 的 same_resource 与 B→A 是同一条事实
        pair = tuple(sorted([edge.src, edge.dst])) + (edge.kind,)
        for e in self.edges:
            if tuple(sorted([e.src, e.dst])) + (e.kind,) == pair:
                return
        self.edges.append(edge)

    def neighbors(self, key: str, kind: Optional[str] = None) -> List[Tuple[Edge, Node]]:
        out: List[Tuple[Edge, Node]] = []
        for e in self.edges:
            if kind is not None and e.kind != kind:
                continue
            other = e.dst if e.src == key else (e.src if e.dst == key else None)
            if other is None:
                continue
            node = self.nodes.get(other)
            if node is not None:
                out.append((e, node))
        return out

    def to_json(self, max_edges: int = 40) -> Dict[str, object]:
        return {"nodes": [n.to_json() for n in list(self.nodes.values())[:60]],
                "edges": [e.to_json() for e in self.edges[:max_edges]],
                "edge_count": len(self.edges)}

    def summary(self) -> str:
        if not self.edges:
            return "图：%d 个资产，没有可连的边" % len(self.nodes)
        detail = "、".join("%s %d" % (k, v) for k, v in sorted(self.kinds().items()))
        return "图：%d 个资产、%d 条边（%s）" % (len(self.nodes), len(self.edges), detail)

    def kinds(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for e in self.edges:
            out[e.kind] = out.get(e.kind, 0) + 1
        return out

    def brief(self) -> Dict[str, object]:
        """给报告用的三行摘要：多少资产、多少边、边都长什么样。

        刻意不带节点和边本身——`to_json()` 那份是给模型看的上下文，
        报告里放 60 个 URL 只会把"结论从哪来"淹掉。
        """
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                "kinds": self.kinds()}


def build(assets: Iterable[object]) -> Graph:
    """从资产列表建图。入参只要有 url/method/status/identity 四个属性。

    规模：discover 一次能给出上百个资产，两两比较是 O(n²)，200 个就是近两万对。
    每对只做两次 URL 归一 + 一次字符串比较，实测可以接受；再大（上千）就该上
    按 `resource` 建索引了，但那时候选池本身也已经没意义了。

    顺序：结构边（同资源 / 同模板 / 父子）→ 响应体引用（refers_to）→
    URL 查询参数引用（param_ref，只有 harvest 带真值时才有）。后两条都要
    "站点上存在对应资源模板"才落得下去，所以必须放在结构边建完之后。
    """
    items = list(assets)
    g = Graph()
    for a in items:
        res = resource_key(a.url)
        # 节点 key 带具体 id（"GET /api/users/7"），resource 才是归一后的模板。
        # 两者都留：key 用来区分"同一模板下的两个对象"，resource 用来判断"是不是同一资源"。
        g.add(Node(key="%s %s" % (a.method.upper(), a.url), url=a.url,
                   method=a.method.upper(), resource=res,
                   identity=getattr(a, "identity", "none"),
                   status=int(getattr(a, "status", 0) or 0)))
    for i, a in enumerate(items):
        ra = resource_key(a.url)
        ma = a.method.upper()
        ha = host_key(a.url)
        for b in items[i + 1:]:
            # 跨主机的同名路径不是同一个资源：两个站都有 /api/users/7，
            # 它们之间没有任何可外推的关系。
            if host_key(b.url) != ha:
                continue
            rb = resource_key(b.url)
            mb = b.method.upper()
            ka = "%s %s" % (ma, a.url)
            kb = "%s %s" % (mb, b.url)
            if ka == kb or (ma == mb and same_endpoint(a.url, b.url)):
                continue                    # 同方法同端点：同一条资产
            if ra == rb:
                if ma != mb:
                    g.link(Edge("same_resource", ka, kb,
                                "同一资源 %s 上出现过 %s 与 %s" % (ra, ma, mb)))
                else:
                    g.link(Edge("sibling_object", ka, kb,
                                "同一资源模板 %s 下的另一个对象" % ra))
                continue
            if _is_child(ra, rb):
                g.link(Edge("child_resource", ka, kb,  # 父 → 子
                            "%s 是 %s 下的单个对象" % (rb, ra)))
            elif _is_child(rb, ra):
                g.link(Edge("child_resource", kb, ka,  # 父 → 子
                            "%s 是 %s 下的单个对象" % (ra, rb)))
    _add_ref_edges(g, items)
    _add_param_ref_edges(g, items)
    return g


def _resources_by_host(items: Sequence[object]) -> Dict[str, List[str]]:
    """主机 → 这台机器上出现过的资源模板。

    必须按主机分开：`/api/users/{id}` 在两个站都有，但 a.test 上的这条
    在 b.test 上打出去只是一个 404。结构边早就按主机隔离了
    （`build` 里的 netloc 比较），两条引用边也得守同一条规矩。
    """
    out: Dict[str, set] = {}
    for a in items:
        out.setdefault(host_key(a.url), set()).add(resource_key(a.url))
    return {host: sorted(res) for host, res in out.items()}


def _add_ref_edges(g: Graph, items: Sequence[object]) -> None:
    """从响应体里读"这个对象引用了谁"，连到对应资源下的那个 id。

    这是三条结构边之外唯一的语义边，克制在这里：只有同时满足
    ① 响应是 JSON、② 字段名是 `xxx_id`（不是裸 `id`、不在噪声表里）、
    ③ 站点上确实存在一个能吃这个 id 的资源模板 时才连。
    缺一条就不连——宁可漏，也不要凭空造出一个不存在的 URL。
    """
    resources = _resources_by_host(items)
    for a in items:
        body = getattr(a, "body", b"") or b""
        if not body:
            continue
        src = "%s %s" % (a.method.upper(), a.url)
        if src not in g.nodes:
            continue
        own = resources.get(host_key(a.url), ())
        for path, stem, value in extract_refs(body, getattr(a, "content_type", None)):
            target = _ref_target(a.url, stem, value, own)
            if target is None:
                continue
            url, resource = target
            g.link(Edge("refers_to", src, "ref %s" % url,
                        "%s 的响应里 %s=%s（指向 %s）" % (a.url, path, value, resource),
                        dst_url=url))


def _ref_target(base_url: str, stem: str, value: str,
                resources: Sequence[str]) -> Optional[Tuple[str, str]]:
    """把"引用"落到一个具体 URL：只有站点上存在对应资源模板时才落得下去。"""
    want = _REF_ALIASES.get(stem.lower(), stem.lower())
    best: Optional[str] = None
    for r in resources:
        if "{id}" not in r:
            continue
        if want not in _resource_stems(r):
            continue
        if best is None or len(r) < len(best):
            best = r                       # 多个候选时取最短的那个（最可能是直系资源）
    if best is None:
        return None
    parts = urlsplit(base_url)
    path = best.replace("{id}", value)
    if "?" in path:
        path, query = path.split("?", 1)
        return urlunsplit((parts.scheme, parts.netloc, path, query, "")), best
    return urlunsplit((parts.scheme, parts.netloc, path, "", "")), best


def _add_param_ref_edges(g: Graph, items: Sequence[object]) -> None:
    """从 URL 的查询参数里读"这个 id 是真的"，连到对应资源下的那个对象。

    和 `refers_to` 的区别只有一点：那条要等响应体，这条在请求里就写着。
    值带真值这件事只有 harvest 才有（证据表里 query 值一律留空），
    所以"页面自己发过 `?user_id=7`"就是这条边唯一的来源——离线证据里它永远为空。

    同样要求站点上存在能吃这个 id 的资源模板；同一个资源换对象交给
    `sibling_object`，这里只做**跨资源**。
    """
    resources = _resources_by_host(items)
    for a in items:
        src = "%s %s" % (a.method.upper(), a.url)
        if src not in g.nodes:
            continue
        mine = urlsplit(a.url).path.rstrip("/")
        own = resources.get(host_key(a.url), ())
        for name, stem, value in param_refs(a.url):
            target = _ref_target(a.url, stem, value, own)
            if target is None:
                continue
            url, resource = target
            if urlsplit(url).path.rstrip("/") == mine:
                continue          # 就是这个资源自己：那是 sibling_object 的事
            g.link(Edge("param_ref", src, "ref %s" % url,
                        "%s 带着 %s=%s（指向 %s），这个对象在页面自己的请求里是活的"
                        % (a.url, name, value, resource), dst_url=url))


def _is_child(parent: str, child: str) -> bool:
    """`/api/users` 是 `/api/users/{id}` 的父资源（只认"多了一段 {id}"这一种）。"""
    p = parent.split("?", 1)[0].rstrip("/")
    c = child.split("?", 1)[0].rstrip("/")
    if not p or p == c:
        return False
    if not c.startswith(p + "/"):
        return False
    return c[len(p) + 1:] == "{id}"


def _cand(template_id: str, url: str, method: str, param_path: Optional[str],
          priority: float, rationale: str) -> object:
    """延迟导入 Candidate：graph 反过来依赖 planner 会成环，这里只在构造时取一次。"""
    from .planner import Candidate
    return Candidate(template_id=template_id, url=url, param_path=param_path,
                     method=method, priority=priority, rationale=rationale,
                     source="graph")


def candidates(g: Optional[Graph], max_out: int = 6) -> List[object]:
    """从图上展开候选。优先级全部低于规则候选，用来补位。

    三条克制：
    - 只在"源节点有成功证据"时展开（status=200 或 status=0 的基线）；
    - 兄弟对象只取 ±1，不做枚举：扫 id 是另一件事，代价和风险都不一样；
    - 每条候选的 rationale 都写明"从哪条边来的"，报告里能回溯。
    """
    if g is None or not g.nodes:
        return []
    out: List[object] = []
    seen = set()
    known = {(n.method.upper(), n.url) for n in g.nodes.values()}
    param_refs_done: Dict[str, int] = {}

    def push(c, skip_known: bool = True) -> None:
        k = c.key()
        if k in seen:
            return
        # 已经是已知资产的 URL 不再当读候选：它已经探过了，再跑一遍是白花预算。
        # 写候选例外：「同资源换方法」本来就是拿已知 URL 换一个方法。
        if skip_known and (c.method.upper(), c.url) in known:
            return
        seen.add(k)
        out.append(c)

    for e in g.edges:
        # ref 边指向的目标还不是节点（它只是别人响应体里的一个 id），
        # 所以要在取节点之前处理。
        if e.kind in ("refers_to", "param_ref"):
            if not e.dst_url:
                continue
            # 一个列表接口常带好几个 `*_id`，全展开会把候选池占满，
            # 同一个源节点只留前两条。
            used = param_refs_done.get(e.src, 0)
            if used >= MAX_PARAM_REF_CANDS:
                continue
            param_refs_done[e.src] = used + 1
            if e.kind == "refers_to":
                push(_cand("idor-object-ref", e.dst_url, e.dst_method, None, 0.42,
                           "引用关系：%s，试读它指向的对象" % e.reason))
            else:
                push(_cand("idor-object-ref", e.dst_url, e.dst_method, None, 0.46,
                           "id 复用：%s，试直读那个对象" % e.reason))
            continue
        src = g.nodes.get(e.src)
        dst = g.nodes.get(e.dst)
        if src is None or dst is None:
            continue
        if e.kind == "same_resource":
            # 谁是可读的那个，就把它当"已确认资源存在"的证据
            reader, writer = (src, dst) if src.method in ("GET", "HEAD") else (dst, src)
            if reader.method not in ("GET", "HEAD") or reader.status != 200:
                continue
            if writer.method not in ("PUT", "PATCH"):
                continue
            push(_cand("idor-write-object", writer.url, writer.method, "body:*", 0.62,
                       "图上同资源换个方法：%s 在 %s 上读到过数据，"
                       "试它是否也接受 %s" % (reader.method, reader.resource, writer.method)),
                 skip_known=False)
        elif e.kind == "sibling_object":
            for node in (src, dst):
                if node.status != 200:
                    continue
                for slot, value in _object_ids(node.url):
                    for step in (1, -1):
                        nxt = _bump(value, step)
                        if nxt is None:
                            continue
                        url = replace_object_id(node.url, slot, nxt)
                        if resource_key(url) != node.resource:
                            continue          # 换完不在同一模板上，说明这段不是对象 id
                        push(_cand("idor-object-ref", url, node.method, None, 0.58,
                                   "图上同模板换对象：%s 的 %s 由 %s 换成 %s"
                                   % (node.resource, slot, value, nxt)))
        elif e.kind == "child_resource":
            parent = g.nodes.get(e.src)
            child = g.nodes.get(e.dst)
            if parent is None or child is None:
                continue
            if parent.method not in ("GET", "HEAD") or parent.status != 200:
                continue
            if child.method not in ("GET", "HEAD"):
                continue
            # 集合能读，说明"这个集合存在"；1 是最可能存在的第一条。
            # 不枚举：扫 id 是另一件事，代价和风险都不一样。
            slots = _object_ids(child.url)
            if not slots:
                continue
            first = replace_object_id(child.url, slots[0][0], "1")
            push(_cand("idor-object-ref", first, child.method, None, 0.45,
                       "图上父子关系：%s 可读，试它下面的第一条对象" % parent.resource))

    # 孤立资源也值得试一步：/api/users/7 用 A 的身份读到了 200，
    # 「8 号归不归我」是最常见的一问。有边的节点走上面对应的展开，
    # 这里只补没有任何边的节点，避免同一件事说两遍。
    linked = set()
    for e in g.edges:
        linked.add(e.src)
        linked.add(e.dst)
    for key, node in g.nodes.items():
        if key in linked or node.method not in ("GET", "HEAD") or node.status != 200:
            continue
        for slot, value in _object_ids(node.url):
            for step in (1, -1):
                nxt = _bump(value, step)
                if nxt is None:
                    continue
                url = replace_object_id(node.url, slot, nxt)
                if resource_key(url) != node.resource:
                    continue
                push(_cand("idor-object-ref", url, node.method, None, 0.50,
                           "已读到 %s（身份 %s），试同一资源下的相邻对象 %s"
                           % (node.url, node.identity, nxt)))
    out.sort(key=lambda c: -c.priority)
    return out[:max_out]
