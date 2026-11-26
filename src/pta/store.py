"""SQLite 索引。表结构与 P0 规格一一对应。

关键约束：evidence 表的主键是 evidence_id，写入用 upsert；
同一次请求重复采样只增加 timing_sample 行与 sample_count。
"""
from __future__ import annotations

import functools
import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement (
  id TEXT PRIMARY KEY,
  scope_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  operator TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  label TEXT NOT NULL,
  identity TEXT NOT NULL,
  method TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  scheme TEXT NOT NULL,
  raw_path TEXT NOT NULL,
  query_json TEXT NOT NULL,
  request_blob TEXT NOT NULL,
  status INTEGER NOT NULL,
  content_type TEXT,
  body_sha256 TEXT NOT NULL,
  body_len INTEGER NOT NULL,
  headers_json TEXT NOT NULL,
  sample_count INTEGER NOT NULL DEFAULT 1,
  ts_first TEXT NOT NULL,
  ts_last TEXT NOT NULL,
  asset_node_id TEXT,
  param_path TEXT,
  payload_class TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_eng ON evidence(engagement_id, label);
CREATE TABLE IF NOT EXISTS timing_sample (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_id TEXT NOT NULL,
  total_ms REAL NOT NULL,
  ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_timing ON timing_sample(evidence_id);
CREATE TABLE IF NOT EXISTS action_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  engagement_id TEXT NOT NULL,
  action_id TEXT,
  tool TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT,
  host TEXT,
  url TEXT,
  level TEXT,
  approval_fp TEXT,
  detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_action_eng ON action_log(engagement_id, ts);
CREATE TABLE IF NOT EXISTS approval (
  fp TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  decision TEXT NOT NULL,
  scope TEXT NOT NULL,
  tool TEXT NOT NULL,
  host TEXT,
  param_path TEXT,
  payload_class TEXT,
  level TEXT NOT NULL,
  decided_by TEXT NOT NULL,
  decided_at TEXT NOT NULL,
  expires_at TEXT,
  note TEXT
);
CREATE TABLE IF NOT EXISTS ptt_node (
  node_id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  parent_id TEXT,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  status TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ptt_eng ON ptt_node(engagement_id);
CREATE TABLE IF NOT EXISTS finding (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  template_id TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  confidence REAL NOT NULL,
  evidence_ids_json TEXT NOT NULL,
  verdict_json TEXT NOT NULL,
  overridden_by TEXT,
  created_at TEXT NOT NULL,
  system_status TEXT
);
CREATE TABLE IF NOT EXISTS label (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  template_id TEXT NOT NULL,
  label TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  by_who TEXT NOT NULL DEFAULT '',
  target_json TEXT NOT NULL DEFAULT '{}',
  verdict_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_label_eng ON label(engagement_id);
CREATE INDEX IF NOT EXISTS idx_label_finding ON label(finding_id);
"""


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _locked(fn):
    """一次写只用一把锁：同一 sqlite3 连接跨线程复用时，两个线程的
    语句会交错进同一个隐式事务，先 commit 的那个会把对方未写完的行
    一起提交（evidence 有行、timing_sample 还没写）。加锁后每条写操作
    是原子的。读不加锁：SQLite 自己串行化。"""

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)

    return wrapper


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # 操作台是常驻进程，CLI 可能同时在打同一个工作区。默认的 busy 超时是 0，
        # 另一头哪怕只写几毫秒也会立刻 `database is locked`；2 秒足够一次证据落盘。
        self.conn.execute("PRAGMA busy_timeout=2000")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def close(self) -> None:
        """关连接。操作台的 ProjectBook 按 LRU 淘汰工作区时调它。

        已经关过的连接再关一次不该抛：淘汰与进程退出会走到同一条路上。
        """
        with self._lock:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass

    def _migrate(self) -> None:
        """给老库补列。`system_status` 是人开始标注之后才需要的：
        它记系统原判，`status` 记最终口径，两者分开才能说清"系统判了几条、
        其中几条被人否掉"。P2.6 之前的库没有这列，补上并留空（读的时候 COALESCE 回 status）。"""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(finding)").fetchall()}
        if "system_status" not in cols:
            self.conn.execute("ALTER TABLE finding ADD COLUMN system_status TEXT")

    # ---------- engagement ----------
    @_locked
    def put_engagement(self, eng_id: str, scope_json: Dict[str, Any], operator: str) -> None:
        # 用 UPSERT 而不是 REPLACE：REPLACE 会先删后插，created_at 变成"最后一次打开"，
        # 多轮报告的排序就乱了
        self.conn.execute(
            "INSERT INTO engagement(id, scope_json, created_at, operator) VALUES (?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET scope_json=excluded.scope_json, "
            "operator=excluded.operator",
            (eng_id, json.dumps(scope_json, ensure_ascii=False), _now(), operator),
        )
        self.conn.commit()

    @_locked
    def list_engagements(self) -> List[sqlite3.Row]:
        """报告要能一次覆盖多个 engagement：先要能列出库里有哪些。"""
        return self.conn.execute(
            "SELECT id, created_at, operator FROM engagement ORDER BY created_at, id"
        ).fetchall()

    # ---------- evidence ----------
    @_locked
    def upsert_evidence(self, ev) -> None:
        cur = self.conn.execute("SELECT sample_count FROM evidence WHERE evidence_id=?", (ev.evidence_id,))
        row = cur.fetchone()
        new_samples = len(ev.timings_ms)
        if row is None:
            self.conn.execute(
                """INSERT INTO evidence(evidence_id, engagement_id, label, identity, method, host, port,
                   scheme, raw_path, query_json, request_blob, status, content_type, body_sha256, body_len,
                   headers_json, sample_count, ts_first, ts_last, asset_node_id, param_path, payload_class)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ev.evidence_id, ev.engagement_id, ev.label, ev.identity, ev.request.method,
                    ev.request.host, ev.request.port, ev.request.scheme, ev.request.raw_path,
                    json.dumps([list(p) for p in ev.request.query]),
                    ev.request_blob, ev.status, ev.content_type, ev.body_sha256, ev.body_len,
                    json.dumps([list(h) for h in ev.headers]), new_samples,
                    ev.ts_first, ev.ts_last, ev.request.asset_node_id, ev.request.param_path,
                    ev.request.payload_class,
                ),
            )
        else:
            self.conn.execute(
                "UPDATE evidence SET sample_count=sample_count+?, ts_last=? WHERE evidence_id=?",
                (new_samples, ev.ts_last, ev.evidence_id),
            )
        for ms in ev.timings_ms:
            self.conn.execute(
                "INSERT INTO timing_sample(evidence_id, total_ms, ts) VALUES (?,?,?)",
                (ev.evidence_id, ms, ev.ts_last),
            )
        self.conn.commit()

    def get_evidence_row(self, evidence_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,))
        return cur.fetchone()

    def list_evidence(self, engagement_id: str, label: Optional[str] = None) -> List[sqlite3.Row]:
        if label:
            cur = self.conn.execute(
                "SELECT * FROM evidence WHERE engagement_id=? AND label=? ORDER BY ts_first",
                (engagement_id, label),
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM evidence WHERE engagement_id=? ORDER BY ts_first", (engagement_id,)
            )
        return list(cur.fetchall())

    # ---------- PTT（任务树） ----------
    @_locked
    def put_node(self, engagement_id: str, node_id: str, parent_id: Optional[str],
                 kind: str, label: str, status: str,
                 detail: Optional[Dict[str, Any]] = None) -> None:
        """同一 node_id 重跑只更新状态 —— 任务树是"当前事实"，不是流水账。

        流水账在 action_log 里；这里要回答的是"这一轮为什么停、哪个候选没跑"。
        """
        self.conn.execute(
            """INSERT OR REPLACE INTO ptt_node(node_id, engagement_id, parent_id, kind, label,
               status, detail_json, ts) VALUES (?,?,?,?,?,?,?,?)""",
            (node_id, engagement_id, parent_id, kind, label, status,
             json.dumps(detail or {}, ensure_ascii=False), _now()),
        )
        self.conn.commit()

    def nodes(self, engagement_id: str, parent_id: Optional[str] = None) -> List[sqlite3.Row]:
        if parent_id is None:
            cur = self.conn.execute(
                "SELECT * FROM ptt_node WHERE engagement_id=? ORDER BY ts, node_id",
                (engagement_id,))
        else:
            cur = self.conn.execute(
                "SELECT * FROM ptt_node WHERE engagement_id=? AND parent_id=? ORDER BY ts, node_id",
                (engagement_id, parent_id))
        return list(cur.fetchall())

    def timings(self, evidence_id: str) -> List[float]:
        cur = self.conn.execute(
            "SELECT total_ms FROM timing_sample WHERE evidence_id=? ORDER BY id", (evidence_id,)
        )
        return [float(r[0]) for r in cur.fetchall()]

    # ---------- 预算账 ----------
    def count_sent(self, engagement_id: str, tool: str = "http_probe") -> int:
        """真出网的请求数：`decision='ok'` 就是"这一发真的发出去了"。

        续跑时用它把预算接上——PTT 记"跑到哪"，账本记"花了多少"，两者都不是内存态。
        被范围拒绝/需要审批/熔断挡下的那几行不算数：那几发没出去。
        """
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM action_log WHERE engagement_id=? AND tool=? AND decision='ok'",
            (engagement_id, tool))
        return int(cur.fetchone()[0])

    def sent_by_host(self, engagement_id: str, tool: str = "http_probe") -> Dict[str, int]:
        cur = self.conn.execute(
            "SELECT host, COUNT(*) FROM action_log WHERE engagement_id=? AND tool=? AND decision='ok' "
            "GROUP BY host", (engagement_id, tool))
        return {r[0] or "": int(r[1]) for r in cur.fetchall()}

    # ---------- action log ----------
    @_locked
    def log_action(
        self,
        engagement_id: str,
        tool: str,
        decision: str,
        reason: str = "",
        host: str = "",
        url: str = "",
        level: str = "",
        approval_fp: str = "",
        action_id: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.conn.execute(
            """INSERT INTO action_log(ts, engagement_id, action_id, tool, decision, reason, host, url,
               level, approval_fp, detail_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                _now(), engagement_id, action_id, tool, decision, reason, host, url, level,
                approval_fp, json.dumps(detail or {}, ensure_ascii=False),
            ),
        )
        self.conn.commit()

    def logs(self, engagement_id: str, decision: Optional[str] = None) -> List[sqlite3.Row]:
        if decision:
            cur = self.conn.execute(
                "SELECT * FROM action_log WHERE engagement_id=? AND decision=? ORDER BY id",
                (engagement_id, decision),
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM action_log WHERE engagement_id=? ORDER BY id", (engagement_id,)
            )
        return list(cur.fetchall())

    # ---------- approvals ----------
    @_locked
    def put_approval(self, rec: Dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO approval(fp, engagement_id, decision, scope, tool, host, param_path,
               payload_class, level, decided_by, decided_at, expires_at, note)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rec["fp"], rec["engagement_id"], rec["decision"], rec["scope"], rec["tool"],
                rec.get("host"), rec.get("param_path"), rec.get("payload_class"), rec["level"],
                rec["decided_by"], rec["decided_at"], rec.get("expires_at"), rec.get("note"),
            ),
        )
        self.conn.commit()

    def get_approval(self, fp: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM approval WHERE fp=?", (fp,))
        return cur.fetchone()

    def list_approvals(self, engagement_id: str,
                       level: Optional[str] = None) -> List[sqlite3.Row]:
        """未过期的放行记录（预授权视图）。

        `decided_at DESC` 而不是按 fp：人看这张表是为了确认"我刚批的那几条在不在"。
        """
        sql = ("SELECT * FROM approval WHERE engagement_id=? AND decision='approve'"
               " AND (expires_at IS NULL OR expires_at > ?)")
        params: List[Any] = [engagement_id, _now()]
        if level:
            sql += " AND level=?"
            params.append(level)
        sql += " ORDER BY decided_at DESC, fp"
        return list(self.conn.execute(sql, params).fetchall())

    @_locked
    def drop_approval(self, fp: str) -> bool:
        """撤销放行：直接删行，下一次 check 会回到 pending_approval。"""
        cur = self.conn.execute("DELETE FROM approval WHERE fp=?", (fp,))
        self.conn.commit()
        return cur.rowcount > 0

    # ---------- findings ----------
    @_locked
    def put_finding(self, rec: Dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO finding(id, engagement_id, template_id, title, status, confidence,
               evidence_ids_json, verdict_json, overridden_by, created_at, system_status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rec["id"], rec["engagement_id"], rec["template_id"], rec["title"], rec["status"],
                rec["confidence"], json.dumps(rec["evidence_ids"]), json.dumps(rec["verdict"]),
                rec.get("overridden_by"), rec["created_at"], rec["status"],
            ),
        )
        self.conn.commit()

    def list_findings(self, engagement_id: str) -> List[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM finding WHERE engagement_id=? ORDER BY created_at DESC", (engagement_id,)
        )
        return list(cur.fetchall())

    def get_finding(self, finding_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM finding WHERE id=?", (finding_id,))
        return cur.fetchone()

    def latest_finding(self, engagement_id: str) -> Optional[sqlite3.Row]:
        """最近一条结论。`pta show --last` 用它，省得让操作者去翻 id。"""
        cur = self.conn.execute(
            "SELECT * FROM finding WHERE engagement_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (engagement_id,),
        )
        return cur.fetchone()

    # ------------------------------------------------------------ 人工标注
    @_locked
    def put_label(self, rec: Dict[str, Any]) -> int:
        """一条人工标注。同一 finding 可以标多次（先 fp 后 tp），历史全留：
        改判本身是信息——说明判定和人的直觉在哪一版发生了分歧。"""
        cur = self.conn.execute(
            """INSERT INTO label(engagement_id, finding_id, template_id, label, note, by_who,
               target_json, verdict_json, created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                rec["engagement_id"], rec["finding_id"], rec["template_id"], rec["label"],
                rec.get("note") or "", rec.get("by_who") or "",
                json.dumps(rec.get("target") or {}), json.dumps(rec.get("verdict") or {}),
                rec["created_at"],
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def labels(self, engagement_id: str, label: Optional[str] = None) -> List[sqlite3.Row]:
        sql = "SELECT * FROM label WHERE engagement_id=?"
        args: List[Any] = [engagement_id]
        if label:
            sql += " AND label=?"
            args.append(label)
        cur = self.conn.execute(sql + " ORDER BY id", args)
        return list(cur.fetchall())

    def latest_label(self, finding_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM label WHERE finding_id=? ORDER BY id DESC LIMIT 1", (finding_id,)
        )
        return cur.fetchone()

    @_locked
    def set_finding_status(self, finding_id: str, status: str, overridden_by: Optional[str],
                           verdict: Optional[Dict[str, Any]] = None) -> bool:
        """只改状态口径，不动证据与置信度：人否掉一条结论时，
        系统当时有多确信这件事本身要留下来，否则事后无法复盘是哪一步骗过了 oracle。"""
        row = self.get_finding(finding_id)
        if row is None:
            return False
        if verdict is None:
            try:
                verdict = json.loads(row["verdict_json"] or "{}")
            except ValueError:
                verdict = {}
        self.conn.execute(
            "UPDATE finding SET status=?, overridden_by=?, verdict_json=? WHERE id=?",
            (status, overridden_by, json.dumps(verdict), finding_id),
        )
        self.conn.commit()
        return True

    def label_stats(self, engagement_id: str) -> List[sqlite3.Row]:
        """按模板统计：系统判了多少、人否了多少。

        confirmed/hypothesis/refuted 三列读的是 **system_status**（系统原判），
        不是 status（最终口径）——否则人一标 fp，同一行就从 confirmed 挪到 refuted，
        看上去像"系统判了 2 条 confirmed、0 条 refuted"变成"1 条 1 条"，
        系统本身的表现就被人的动作盖住了。
        """
        cur = self.conn.execute(
            """SELECT f.template_id AS template_id,
                      COUNT(*) AS findings,
                      SUM(CASE WHEN COALESCE(f.system_status, f.status)='confirmed' THEN 1 ELSE 0 END) AS confirmed,
                      SUM(CASE WHEN COALESCE(f.system_status, f.status)='hypothesis' THEN 1 ELSE 0 END) AS hypothesis,
                      SUM(CASE WHEN COALESCE(f.system_status, f.status)='refuted' THEN 1 ELSE 0 END) AS refuted,
                      SUM(CASE WHEN COALESCE(f.system_status, f.status)='pending_approval' THEN 1 ELSE 0 END) AS pending,
                      (SELECT COUNT(*) FROM label l WHERE l.engagement_id=f.engagement_id
                          AND l.template_id=f.template_id AND l.label='fp') AS fp,
                      (SELECT COUNT(*) FROM label l WHERE l.engagement_id=f.engagement_id
                          AND l.template_id=f.template_id AND l.label='tp') AS tp
               FROM finding f WHERE f.engagement_id=?
               GROUP BY f.template_id ORDER BY findings DESC, f.template_id""",
            (engagement_id,),
        )
        return list(cur.fetchall())
