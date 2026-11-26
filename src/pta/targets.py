# -*- coding: utf-8 -*-
"""目标台账：把"那堆 --root 到底哪个是哪个"变成一个能记住的簿子。

动机很土：一个工作区就是一个目录，目录名是用户自己起的。做第三个目标的时候，
`--root /path/to/lab2` 已经想不起来装的是什么了，得先去翻 scope.json。
不想翻的代价通常是——干脆不建新工作区，把新目标塞进旧的里，然后两边的预算和
结论混在一起。

**台账只记路径，不复制真相。** 域、预算、结论数都现场从 `scope.json` 和
`store.db` 读：如果台账里也存一份，迟早会和真实工作区对不上，而那种对不上
比没有台账更坏——你会相信它。

别名是可以直接喂给 `--root` 的：`--root lab2` 会在所有命令里被解析成真实路径。
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
from typing import Any, Dict, List, Optional

VERSION = 1
DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".pta")


class LedgerError(ValueError):
    pass


def home() -> str:
    """台账放哪。`PTA_HOME` 覆盖（测试与便携用法都需要）。"""
    return os.environ.get("PTA_HOME") or DEFAULT_HOME


def ledger_path() -> str:
    return os.path.join(home(), "targets.json")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load() -> Dict[str, Any]:
    path = ledger_path()
    if not os.path.exists(path):
        return {"version": VERSION, "targets": []}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise LedgerError("台账读不出来（%s）：%s" % (path, exc))
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise LedgerError("台账格式不对：%s" % path)
    data.setdefault("version", VERSION)
    return data


def save(data: Dict[str, Any]) -> str:
    """原子写。半截的 JSON 会让下一次 `pta ls` 直接炸，而那正是最不想它炸的时刻。

    写不进去（`~/.pta` 被策略挡了、盘满了、路径是只读挂载）必须变成 LedgerError：
    台账是"顺手记一笔"的东西，它失败了不该让 `pta init` 跟着失败。
    """
    path = ledger_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".targets-", dir=os.path.dirname(path))
    except OSError as exc:
        raise LedgerError("台账写不进去（%s）：%s；用 PTA_HOME 指到可写目录"
                          % (path, exc)) from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except OSError as exc:
        raise LedgerError("台账写不进去（%s）：%s；用 PTA_HOME 指到可写目录"
                          % (path, exc)) from exc
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path


def _key(root: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(root)))


def entries() -> List[Dict[str, Any]]:
    """按最后使用时间降序。没有 last_used_at 的按登记时间算。"""
    rows = load()["targets"]
    rows.sort(key=lambda r: (r.get("last_used_at") or r.get("created_at") or ""), reverse=True)
    return rows


def get(name: str) -> Optional[Dict[str, Any]]:
    """按别名或路径找一条。路径用 realpath 归一，`lab2` 和 `D:\\lab2\\` 是同一个。"""
    if not name:
        return None
    want = _key(name)
    for row in load()["targets"]:
        if row.get("alias") == name:
            return row
        if _key(row.get("root") or "") == want:
            return row
    return None


def resolve(name: str) -> Optional[str]:
    """把别名/路径变成真实路径。解析不出来返回 None（调用方决定是报错还是当路径用）。"""
    row = get(name)
    if row is None:
        return None
    root = row.get("root") or ""
    return os.path.abspath(root) if root else None


def _fresh_alias(want: str, taken: set) -> str:
    base = want or "target"
    if base not in taken:
        return base
    for n in range(2, 100):
        cand = "%s-%d" % (base, n)
        if cand not in taken:
            return cand
    raise LedgerError("别名 %s 的后缀用完了（真的？）" % want)


def register(root: str, engagement_id: str = "", domains=(), alias: str = "",
             note: str = "", name: str = "") -> Dict[str, Any]:
    """登记一个工作区。同一个路径重复登记只更新别名/备注，不产生第二条。"""
    real = os.path.abspath(root)
    if not os.path.isdir(real):
        raise LedgerError("目录不存在：%s" % real)
    data = load()
    rows = data["targets"]
    key = _key(real)
    for row in rows:
        if _key(row.get("root") or "") == key:
            if alias:
                row["alias"] = alias
            if note:
                row["note"] = note
            if name:
                row["name"] = name
            if engagement_id:
                row["engagement_id"] = engagement_id
            if domains:
                row["domains"] = list(domains)
            row["last_used_at"] = _now()
            save(data)
            return row
    taken = {r.get("alias") for r in rows}
    row = {
        "alias": _fresh_alias(alias or engagement_id, taken),
        "name": name or "",
        "root": real,
        "engagement_id": engagement_id,
        "domains": list(domains),
        "note": note,
        "created_at": _now(),
        "last_used_at": _now(),
    }
    rows.append(row)
    save(data)
    return row


def touch(name: str) -> Optional[Dict[str, Any]]:
    row = get(name)
    if row is None:
        return None
    data = load()
    for r in data["targets"]:
        if r.get("alias") == row.get("alias"):
            r["last_used_at"] = _now()
            break
    save(data)
    return row


def forget(name: str) -> bool:
    row = get(name)
    if row is None:
        return False
    data = load()
    before = len(data["targets"])
    data["targets"] = [r for r in data["targets"] if r.get("alias") != row.get("alias")]
    save(data)
    return len(data["targets"]) != before


def set_delivery(name: str, delivered: bool, by: str = "operator", note: str = "") -> Dict[str, Any]:
    """记一次「交付 / 撤回交付」。

    为什么不写进工作区：交付是人的决定，不是工作区里的真相。目录被删、被重建、
    被拷走，都不该让"这一轮已经交出去了"这件事消失或复活。台账本来就是记
    这类事的簿子（它记的"只记路径"，指的是域和结论数不复制；人的动作得存）。
    """
    row = get(name)
    if row is None:
        raise LedgerError("台账里没有 %r" % (name,))
    data = load()
    alias = row.get("alias")
    for r in data["targets"]:
        if r.get("alias") != alias:
            continue
        if delivered:
            r["delivered_at"] = _now()
            r["delivered_by"] = by or "operator"
            r["delivered_note"] = note or ""
        else:
            r["delivered_at"] = None
            r["delivered_by"] = None
            r["delivered_note"] = ""
        r["last_used_at"] = _now()
        save(data)
        return r
    raise LedgerError("台账里没有 %r" % (name,))


def summary(row: Dict[str, Any]) -> Dict[str, Any]:
    """一条台账 + 现场读到的真相。读不到的字段留空并带 `error`，不编。"""
    out = {
        "alias": row.get("alias"),
        # 名字是给人看的；老台账行没有这个名字，回落到别名
        "name": row.get("name") or row.get("alias"),
        "root": row.get("root"),
        "engagement_id": row.get("engagement_id"),
        "domains": list(row.get("domains") or ()),
        "note": row.get("note") or "",
        "created_at": row.get("created_at"),
        "last_used_at": row.get("last_used_at"),
        # 交付是人的决定，不是工作区的真相，所以它只活在这本台账里
        "delivered_at": row.get("delivered_at"),
        "delivered_by": row.get("delivered_by"),
        "delivered_note": row.get("delivered_note") or "",
        "exists": False,
        "findings": 0,
        "confirmed": 0,
        "requests_used": 0,
        "last_activity": "",
        "fresh": False,
    }
    root = row.get("root") or ""
    if not os.path.isdir(root):
        out["error"] = "目录不在了"
        return out
    out["exists"] = True
    scope_path = os.path.join(root, "scope.json")
    try:
        with open(scope_path, encoding="utf-8") as fh:
            scope = json.load(fh)
        out["engagement_id"] = scope.get("engagement_id") or out["engagement_id"]
        out["domains"] = list(scope.get("domains") or out["domains"])
    except (OSError, ValueError) as exc:
        out["error"] = "scope.json 读不出来（%s）" % exc

    db = os.path.join(root, "index.sqlite")
    if not os.path.exists(db):
        # 刚 init 还没跑过。这不是错误，别在表格里显示成异常
        out["fresh"] = True
        return out
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db.replace("\\", "/"), uri=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*), SUM(CASE WHEN status='confirmed' THEN 1 ELSE 0 END)"
                        " FROM finding")
            total, confirmed = cur.fetchone()
            out["findings"] = int(total or 0)
            out["confirmed"] = int(confirmed or 0)
            cur.execute("SELECT COUNT(*) FROM evidence")
            out["requests_used"] = int(cur.fetchone()[0] or 0)
            cur.execute("SELECT MAX(ts_last) FROM evidence")
            out["last_activity"] = cur.fetchone()[0] or ""
        finally:
            conn.close()
    except sqlite3.Error as exc:
        out["error"] = "index.sqlite 读不出来（%s）" % exc
    return out


def listing() -> List[Dict[str, Any]]:
    return [summary(r) for r in entries()]


def render(rows: List[Dict[str, Any]]) -> List[str]:
    if not rows:
        return ["台账里还没有目标：`pta init --root <目录> --engagement <名字> --domain <域>` 会自动登记。"]
    lines = ["  %-12s %-34s %-18s %-5s %-5s %s"
             % ("别名", "目录", "域", "结论", "确认", "最后活动")]
    for r in rows:
        flag = "" if r.get("exists") else "（目录不在了）"
        if r.get("error") and r.get("exists"):
            flag = "（%s）" % r["error"]
        lines.append("  %-12s %-34s %-18s %-5d %-5d %s%s"
                     % (_short(r.get("alias") or "-", 12),
                        _short(r.get("root") or "-", 34),
                        _short(",".join(r.get("domains") or []) or "-", 18),
                        r.get("findings") or 0, r.get("confirmed") or 0,
                        r.get("last_activity") or "-", flag))
    lines.append("")
    lines.append("别名可以直接当 --root 用：`pta run --root %s ...`"
                 % (rows[0].get("alias") or "<别名>"))
    return lines


def _short(text: str, width: int) -> str:
    text = str(text)
    if len(text) <= width:
        return text
    # 路径两头都有用：开头能看出盘符/父目录，末尾是目录名本身（识别靠它）。
    # 全砍左边会变成「…0RX4\w-blog」，看不出这行到底是哪个盘。
    head = max(2, (width - 1) // 2)
    tail = width - 1 - head
    return text[:head] + "…" + (text[-tail:] if tail > 0 else "")
