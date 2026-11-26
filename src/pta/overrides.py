"""模板覆盖层：让校准结果直接生效，而不是让人手抄进模板。

校准器给的是"这个目标上的阈值应该是多少"，但它不能改模板本身——模板是资产，
一份模板要服务很多目标，把某次测量结果写死进去会让下一次演练继承上一次的假设。

所以覆盖层放在工作区：`<root>/overrides.json`，形如

    {"templates": {"sqli-time-blind": {
        "oracle": {"args": {"cv_max": 0.5, "min_effect_ms": 1200}},
        "probe": {"samples": 10}
    }}}

**只允许调阈值，不允许改判定。** 白名单只有三条路径：
`oracle.args.*`（阈值/参数）、`probe.samples`（采样数）、`probe.timeout_s`（超时）。
`side_effect_level`、`oracle.name`、`requires_approval`、`mutator_hints` 这些一律拒——
否则一份 overrides.json 就能把 L2 改成 L0，把审批门绕开，那五条不变量就白写了。
"""
from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict, List, Optional, Tuple

import pta.vhx as vhx

FILE_NAME = "overrides.json"

# (路径前缀, 说明)：只按前缀匹配，深层键（oracle.args 下的具体参数）不限制
ALLOWED: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (("oracle", "args"), "判定参数（阈值等）"),
    (("probe", "samples"), "采样次数"),
    (("probe", "timeout_s"), "单次请求超时"),
)


class OverrideError(Exception):
    """覆盖层里出现了不该被覆盖的字段。"""


def path_for(ws) -> str:
    return os.path.join(ws.root, FILE_NAME)


def read(ws) -> Dict[str, Dict[str, Any]]:
    path = path_for(ws)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise OverrideError("%s 不是一个对象" % path)
    out = data.get("templates") or {}
    if not isinstance(out, dict):
        raise OverrideError("%s 的 templates 不是对象" % path)
    return out


def write(ws, templates: Dict[str, Dict[str, Any]]) -> str:
    """先全量校验再落盘：宁可写不进去，也不留下半份能绕门的覆盖。"""
    for tid, frag in templates.items():
        _validate(frag, tid)
    path = path_for(ws)
    payload = {"version": 1, "templates": templates}
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def clear(ws) -> bool:
    path = path_for(ws)
    if os.path.exists(path):
        os.unlink(path)
        return True
    return False


def _walk(frag: Any, prefix: Tuple[str, ...], template_id: str) -> List[Tuple[Tuple[str, ...], Any]]:
    if isinstance(frag, dict):
        out: List[Tuple[Tuple[str, ...], Any]] = []
        for k, v in frag.items():
            out.extend(_walk(v, prefix + (str(k),), template_id))
        return out
    return [(prefix, frag)]


def _validate(frag: Dict[str, Any], template_id: str) -> None:
    if not isinstance(frag, dict):
        raise OverrideError("模板 %s 的覆盖不是对象" % template_id)
    for keypath, value in _walk(frag, (), template_id):
        ok = any(keypath[: len(prefix)] == prefix for prefix, _ in ALLOWED)
        if not ok:
            allowed = "、".join(".".join(p) for p, _ in ALLOWED)
            raise OverrideError(
                "不能覆盖 %s.%s：只允许调 %s（阈值可以调，判定不能改）"
                % (template_id, ".".join(keypath), allowed))
        if isinstance(value, (dict, list)):
            raise OverrideError("%s.%s 只能是标量" % (template_id, ".".join(keypath)))


def apply_to(raw: Dict[str, Any], frag: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """深拷贝后合并。原模板对象永远不被改——同一进程里还要服务别的目标。"""
    out = copy.deepcopy(raw)
    if not frag:
        return out
    _validate(frag, str(raw.get("id") or "?"))
    for key, value in frag.items():
        target = out.setdefault(key, {})
        if not isinstance(target, dict) or not isinstance(value, dict):
            raise OverrideError("覆盖 %s 的形状不对" % key)
        _merge(target, value)
    return out


def _merge(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


def load_template(ws, template_id: str) -> Tuple[vhx.Template, Dict[str, Any]]:
    """按"内置模板 + 工作区覆盖"加载。返回 (模板, 实际生效的覆盖片段)。"""
    raw = None
    for t in vhx.TEMPLATES:
        if t.get("id") == template_id:
            raw = t
            break
    if raw is None:
        raise KeyError(template_id)
    frag = (read(ws) or {}).get(template_id) or {}
    merged = apply_to(raw, frag)
    return vhx.load(merged), copy.deepcopy(frag)


def from_suggestion(suggestion: Dict[str, Any], samples: Optional[int] = None) -> Dict[str, Any]:
    """把校准器的建议转成覆盖片段。"""
    args = {k: v for k, v in suggestion.items()
            if k in ("min_samples", "cv_max", "abs_noise_ms", "min_effect_ms", "alpha")}
    frag: Dict[str, Any] = {}
    if args:
        frag["oracle"] = {"args": args}
    n = samples if samples is not None else suggestion.get("samples")
    if n:
        frag.setdefault("probe", {})["samples"] = int(n)
    return frag


def describe(templates: Dict[str, Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for tid in sorted(templates):
        for keypath, value in _walk(templates[tid], (), tid):
            lines.append("%s: %s = %s" % (tid, ".".join(keypath), json.dumps(value, ensure_ascii=False)))
    return lines
