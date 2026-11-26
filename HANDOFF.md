# PTA — 项目交接文档

> 写给下一个接手这个仓库的人（或者三个月后的你自己）。
> 只讲三件事：**它是什么、代码在哪、怎么安全地改**。
> 仓库：`<repo>`　语言：Python 3.8（纯标准库）　形态：命令行 + 本地操作台
> 规模：`src/pta/` 40 个模块约 13k 行，`src/pta/ui/` 三个文件约 2k 行，测试 846 项

---

## 1. 一句话

一个**自用**的、证据驱动的 Web 渗透测试助手：从一个首页开始自己找资产、提候选、发请求、把响应存成可重算的证据，
再用确定性判定器把候选变成 `confirmed / hypothesis / refuted`，最后把 confirmed 还原成一条能直接执行、能复现的请求。

它不做的事同样重要：不自动决定"打哪个"、不自动升级权限、不在没有证据时给结论、不删除/不爆破/不做拒绝服务。

---

## 2. 设计上的四条硬线

这四条决定了代码为什么长这样。改代码前先读这一节，能省掉一半返工。

1. **判定与采集分离**。`probe` 只负责"发一次请求、存一条证据"；`oracle` 只负责"看证据、给结论"。
   任何一个 oracle 都不许自己发请求（除了显式的 OOB 检查），否则证据链断掉、结论无法复算。
2. **一切可重算**。`evidence_id = sha256(canonical_request + body_sha256 + label)[:64]`（见 `probe.compute_evidence_id`）。
   时间不参与，所以同一请求采样 5 次＝同一条证据；两个不同的人拿到同一对请求/响应，会算出同一个 id。
3. **危险动作要人点**。L2+ 动作在 `executor` 里被拦下，落到 `approval` 表，操作台/CLI 里点了才放行。
   指纹是 `sha256(tool|host|param_path|payload_class|level)[:24]`，`once` 用后即焚，`class` 带 TTL。
4. **停下来必须能解释**。每个阶段都有 `why`：`discover` 有诊断块，`planner` 有 `rationale`，`projects` 有 `why_stopped`。
   一个工具"没结果"和"跑挂了"必须是两种输出。

判定阈值（`verdict_status`）：≥0.85 `confirmed`，≥0.60 `hypothesis`，其余 `refuted`。
**凡是 `Verdict(passed=True)`，置信度必须 ≥0.85**，否则界面会出现"通过了但写否"的自相矛盾（踩过两次）。

---

## 3. 五分钟跑起来

```powershell
cd <repo>
$env:PYTHONPATH='src'
$env:PYTHONIOENCODING='utf-8'

python -m unittest discover -s tests      # 846 项，约 3.5 分钟
python demo_run.py                        # 一条完整的执行闭环，末行 OK
python -m pta.cli ui                      # 操作台 http://127.0.0.1:8765/
```

可选依赖只有一个：`cryptography`（装了就用 AES-256-GCM 加密证据正文；没装会明文存并告警）。

**两个环境变量值得知道**：

| 变量 | 作用 |
| --- | --- |
| `PTA_HOME` | 目标台账目录，默认 `~/.pta`。沙箱/CI 里指向可写目录，否则建项目会挂住 |
| `PTA_BROWSER` | Chrome/Edge 可执行文件路径，`--browser` 与 `browser_nav` 模板要用 |

---

## 4. 数据流：一条候选的一生

```
① crawl / discover            首页 → 页面、接口、参数名 → recon.json
        │                        （--browser 时再并入页面自己发的请求）
        ▼
② planner                     证据 + 资产图 → 候选（模板 + URL + 参数 + 身份 + 优先级 + 理由）
        │                        规则：?id= / 写方法 / 需两身份的接口
        │                        图：child_resource / sibling_object / same_resource
        │                            refers_to / param_ref（后两类是跨对象外推）
        ▼
③ executor + probe            候选 → 动作序列 → 每一次 http_request 落一条 evidence
        │                        L2+ 先落 approval，等人点
        ▼
④ oracle                      evidence → Observation → Verdict(metrics, rationale, title)
        │                        只有这里能下结论，且必须确定性
        ▼
⑤ store                       finding + 证据 id 列表 + verdict JSON
        ▼
⑥ critic / labels             复核（降级）、标误报（保留原判）、算误报率
        ▼
⑦ poc / report                confirmed → curl/powershell/python/raw；报告 → 单文件 HTML
```

每一环的产物都落盘，所以任何一步都能单独重跑（`--resume` 从账本恢复预算与进度）。

---

## 5. 代码板块对应表

### 5.1 基础层（先读这七个，其余都是组合）

| 模块 | 行 | 职责 | 关键符号 |
| --- | ---: | --- | --- |
| `models.py` | 269 | 领域模型与规范化 | `Scope` `Asset` `Observation` `Verdict` `Finding` `Extract` `canonical_query` `body_sha256` |
| `errors.py` | 19 | 异常族 | `ScopeViolation` `TransportError` `ApprovalRequired` |
| `scope.py` | 120 | **发请求前唯一的守门人** | `Scope.check_request`（域名/端口/方法/路径/私有地址/速率） |
| `transport.py` | 219 | 真 socket 收发 | `DirectPinnedTransport.send` `_read_response` `_ReplaySocket` `MockTransport`/`MockRoute`（测试用） |
| `cas.py` | 162 | 内容寻址存储 | `Cas.put/get`，`hash=sha256(body)`，主密钥在 `vault.json` |
| `store.py` | 424 | SQLite 账本 | 8 张表，见 §7；`put_finding` `list_findings` `log_action` `list_approvals` |
| `workspace.py` | 141 | 把上面几样拼成一个工作区 | `open_workspace` `init_workspace` `.probe .store .cas .vault .scope .bus` |

### 5.2 采集层

| 模块 | 行 | 职责 |
| --- | ---: | --- |
| `probe.py` | 467 | 一次请求 → 一条证据。`ProbeTool.run(ProbeRequest)`；含通道标注、采样、重定向跟随、`compute_evidence_id` |
| `recon.py` | 285 | 爬取：同主机链接、表单、JS 里的接口；记录 `final_url` 与被拦下的跳转 `blocked_redirects` |
| `cdp.py` | 199 | DevTools 协议最小客户端（WebSocket 手写帧） |
| `browser.py` | 586 | 真浏览器：`BrowserProcess`（起进程/读日志）、`BrowserTool`（导航、执行、注入身份 cookie） |
| `harvest.py` | 164 | `Network.*` 事件 → 调用形状（method+url+body 字段），去重 |
| `channels.py` | 231 | 三档通道消歧：`plain` / `browser` / `curl`，识别 WAF/拦截页特征 |
| `oob.py` | 240 | 带外收集器（HTTP + DNS），供 SSRF/XXE 用 |
| `replay.py` | 81 | 用证据里的请求重放一次（复核用） |

### 5.3 决策层

| 模块 | 行 | 职责 |
| --- | ---: | --- |
| `graph.py` | 604 | 资产邻接图：五类边 + `host_key`（默认端口归一）+ `candidates()`（克制：每源最多 2 条、跨对象只在本主机内匹配） |
| `planner.py` | 710 | 候选生成：`PlannerState.collect`、`_rule_candidates`、`heuristic_candidates`、`MAX_GRAPH_SLOTS=4`（给图外推留位子） |
| `discover.py` | 476 | 侦察→候选的一站式入口，含 `--browser`、合并 harvest 资产、`_diagnose` 诊断块 |
| `overrides.py` | 120 | 工作区级阈值覆盖（`overrides.json`），复核校准用 |
| `calibrate.py` | 222 | 用历史证据重算阈值（"先量噪声再定阈值"） |
| `llm.py` | 199 | 可选的模型接入：只允许补充理由/否决，不许改判 |
| `critic.py` | 250 | 自动复核：篡改证据、同身份配置、单证据、重放、模型否决 |
| `labels.py` | 149 | 人工裁决：标误报、保留原判、误报率（分母只算人看过的） |

### 5.4 动作层

| 模块 | 行 | 职责 |
| --- | ---: | --- |
| `vhx.py` | 1069 | **23 个模板 + 20 个 oracle 的注册表**：`TEMPLATES` `ORACLE_REGISTRY` `ACTIONS` `PRECONDITIONS` |
| `payloads.py` | 146 | 载荷类与拼接方式（`append` vs `replace`——SQL 注入必须 append） |
| `executor.py` | 832 | 模板 → 动作序列：`Executor.run` `Target` `_finalize`；审批、通道、预算都在这里收口 |
| `runner.py` | 710 | 一轮多候选并发执行、任务树（PTT）、`--resume` 断点续跑 |
| `oracles.py` | 1483 | 20 个判定器实现（`ErrorSignatureMatch` `AuthzTemplateDiff` `BatchUnauthorizedRead` …） |
| `jwtlab.py` | 65 | JWT 变形（`alg=none`、去签名、算法混淆） |
| `approvals.py` | 87 | 审批指纹与作用域判定 |
| `grants.py` | 190 | 预授权：`Spec`→`expand`→`grant(ttl)`；`audit` 只读日志 |
| `budget.py` | 110 | 预算账本（硬上限） |
| `credentials.py` | 199 | cURL/头/cookie 文件解析、掩码、注入 |

### 5.5 输出层

| 模块 | 行 | 职责 |
| --- | ---: | --- |
| `poc.py` | 281 | 结论 → 可执行请求：`curl` / `powershell` / `python` / `raw`；角色挑证据、vault 解密文 |
| `report.py` | 526 | 报告：Markdown + 单文件 HTML（内联样式、无外链）、多轮合并、脱敏 |
| `targets.py` | 266 | 目标台账 `~/.pta/targets.json`：只记路径/别名/交付，**不存结论** |
| `projects.py` | 709 | 多项目：八档阶段（现算）、六步时间线、交付、`JobRegistry` 后台任务 |
| `api.py` | 752 | 操作台 HTTP API + 静态文件白名单 |
| `cli.py` | 1085 | 34 个子命令的入口 |
| `ui/` | 2k | `index.html` + `app.js`（零依赖 IIFE）+ `style.css`，无构建、无 CDN |

---

## 6. 五条不变量落在哪一行

| 不变量 | 落点 |
| --- | --- |
| scope 校验在发请求之前 | `scope.Scope.check_request`；只有 `transport.DirectPinnedTransport.send` 和 `probe` 会调它 |
| 预算硬上限 | `budget.Budget` + `store.count_sent`；`executor` 每次动作前扣 |
| 证据可重算 | `probe.compute_evidence_id`（时间不参与）+ `cas` 按 sha256 寻址 |
| L2+ 需审批 | `executor` 的 `ApprovalRequired` → `approvals.fingerprint` → `store.put_approval` → `api`/`cli` 放行 |
| oracle 确定性 | `oracles.py` 里所有判定只读 `Observation`；`tests/test_oracles.py` 有逐字节复算断言 |

---

## 7. 落盘结构与数据

一个工作区（= 一个项目 = 一个 `--root`）：

```
工作区/
├─ scope.json        Scope 的冻结副本（域名/端口/速率/预算/到期/deny_paths）
├─ index.sqlite      账本（8 张表）
├─ cas/              证据正文，按 sha256 分桶；主密钥在 vault.json
├─ vault.json        凭证与主密钥（cred/<身份>/<header> → 值）
├─ discover.json     最近一次 discover 的明细（候选、图、诊断）
├─ recon.json        最近一次 crawl 的明细（页面、接口、被跳过的链接）
├─ overrides.json    可选，阈值覆盖
└─ logs/             动作日志导出（可选）
```

SQLite 八张表：

| 表 | 存什么 | 关键列 |
| --- | --- | --- |
| `engagement` | 一次演练 | `id`（= 工作区名）、`scope_json`、`operator` |
| `evidence` | 一个请求+响应的元数据 | `evidence_id`、`method/host/port/scheme/raw_path`、`status`、`body_sha256`、`label`、`identity`、`headers_json` |
| `timing_sample` | 时间盲注的采样 | `evidence_id`、耗时序列 |
| `action_log` | 每个动作 | `decision`、`detail_json`（含 `redirects`/`redirect_blocked`/`evidence_id`） |
| `approval` | 待批/已批 | `fp`、`level`、`scope`、`expires_at` |
| `ptt_node` | 任务树 | `node_id`、`parent_id`、状态 |
| `finding` | 结论 | `id`(16 hex)、`template_id`、`status`、`confidence`、`verdict_json`、`evidence_ids_json` |
| `label` | 人工裁决 | `finding_id`、`label`、`note`、`by_who`、`target_json`、`verdict_json`（留原判） |

目标台账 `~/.pta/targets.json`（可用 `PTA_HOME` 改位置）：只记 `root/alias/name/domains/note/created_at/last_used_at/delivered_*`。
**它有意的与结论分离**——删掉台账不会丢结论，删掉工作区才会。

---

## 8. 23 个模板 ↔ 20 个 oracle

| 模板 | 级别 | oracle | 证据形状要点 |
| --- | --- | --- | --- |
| `idor-object-ref` | L1 | `differential_object_access` | 两身份同 URL 的差异 + 负对照 |
| `idor-batch-sweep` | L1 | `batch_unauthorized_read` | 连续 id 的可读比例分层 |
| `authz-missing-endpoint` | L1 | `authz_template_diff` | 无凭据/另一身份对比；同字节要提示"可能全局共享" |
| `info-disclosure-artifact` | L0 | `file_signature_match` | 文件签名（堆栈/目录列表/.env…）+ 容器负对照 |
| `sqli-error-boolean` | L1 | `error_signature_match` | 报错特征（mysql/pgsql/oracle/mssql/sqlite） |
| `sqli-boolean-blind` | L1 | `boolean_response_split` | `1=1` 与 `1=2` 的响应被掰开 |
| `sqli-time-blind` | L2 | `timing_distribution_shift` | 延时分布 vs 基线噪声 |
| `ssrf-outbound` | L2 | `oob_callback_received` | 带外回连 |
| `ssrf-internal-service` | L2 | `internal_service_fingerprint` | 内网服务回显指纹（3s 超时） |
| `path-traversal-lfi` | L1 | `file_signature_match` | 读到的文件签名 |
| `open-redirect` | L1 | `redirect_target_match` | 落地地址 |
| `jwt-trust-boundary` | L1 | `jwt_acceptance_check` | 变形后的 token 仍被接受 |
| `xss-reflected` | L1 | `dom_marker_present` | 脚本真的执行了（真浏览器） |
| `xss-stored-marker` | L2 | `stored_marker_reflected` | 写入的标记被原样渲染（要 `--verify-url` 回读） |
| `csrf-token-not-enforced` | L2 | `csrf_token_not_enforced` | 摘令牌两态 + 匿名对照 |
| `mass-assignment-privilege` | L2 | `field_escalation_effect` | 多塞的权限字段被写库 |
| `idor-write-object` | L2 | `write_effect_visible` | 属主回读能看到改动 |
| `upload-rce` | L2 | `upload_readback` | 回读命中本次随机标记 |
| `xxe-entity` | L2 | `oob_callback_received` | 带外确认 |
| `deserialization-marker` | L1 | `deserialization_marker_present` | 解析到类名后报错 |
| `race-condition-idempotency` | L2 | `idempotency_violation` | 并发突发下同一操作被接受多次 |
| `logic-negative-amount` | L2 | `numeric_boundary_accepted` | 回读命中 `expect_value` |
| `logic-quantity-overflow` | L2 | `numeric_boundary_accepted` | 同上，边界不同 |

12 个动作原语：`http_request` `mutate_param` `swap_identity` `diff_response` `timing_sample` `batch_sweep`
`concurrent_burst` `replay` `oob_arm` `oob_check` `browser_nav` `decode_token`。

---

## 9. CLI 速查（34 个子命令）

| 组 | 命令 |
| --- | --- |
| 建/查 | `init` `ls` `forget` `state` `tree` `logs` |
| 手动 | `probe` `crawl` `discover` `plan` `run` `auto` `replay` `oob` `harvest` |
| 结论 | `show` `critic` `mark` `labels` `stats` `calibrate` `verify` |
| 审批 | `approve` `grant` `grants` `revoke` `audit` |
| 身份 | `auth`（add/ls/check/rm） |
| 输出 | `report` `ui` |
| 其它 | `overrides` `check` |

最常用的六条：

```powershell
python -m pta.cli crawl    --root WS --seed https://t/ --max-pages 12 --max-depth 2
python -m pta.cli discover --root WS --seed https://t/ --identity A --write
python -m pta.cli run      --root WS --template idor-object-ref --url "https://t/api/users/7" --identity-baseline A --identity-probe B
python -m pta.cli show     --root WS --last --as powershell
python -m pta.cli report   --root WS --out out --html
python -m pta.cli ui       --workspace WS
```

---

## 10. 操作台（前端）

三个视图：`#/` 项目列表、`#/new` 新建、`#/p/<alias>` 详情（六步时间线 + 四面板 + 后台任务）。
四面板只读：假设队列 / 资产图（右上「提候选」，**候选行可点，点了直接填进跑模板**）/ 审批栏 / 证据对比。

三个刻意的设计：

1. `/api/run` 异步（202 + `run_id`，结论走 SSE），否则跑时间盲注会把浏览器卡住十几秒。
2. 证据原文要 `confirm=1` 才给（响应体可能含他人信息）。
3. 对比用 `difflib` 而不是行集合：单行 JSON 只差一个字段时，行集合会掉到 0.39，`SequenceMatcher` 给 0.93。

改视觉请先读 `UI-HANDOFF.md`（DOM id 契约、10 条硬约束、CSS 变量语义）。

---

## 11. 测试与验收

| 层 | 数量 | 覆盖 |
| --- | ---: | --- |
| `tests/test_*.py` | 846 项 / 约 50 个文件 | 每层都有：scope、transport、probe、store、cas（`test_evidence`）、每个 oracle、每个模板端到端、API、前端静态页、路由与项目 |
| `demo_*.py` | 35 个 | 全离线，每个末行必 OK；`demo_run.py` 是主闭环，`demo_projects.py` 是多项目壳 |
| `live_check.py` | 1 | 真实 socket（含 SSRF 带外），跑在本机回环上 |
| `acceptance.py` | 1 | P0 六条验收 |

约定：**新增能力必须同时给测试和 demo**，且 demo 的末行是 `OK`（脚本自己数 checks）。
跑全量：`python -m unittest discover -s tests`（约 3.5 分钟）。

---

## 12. 踩过并且值得记住的坑

| 症状 | 根因 | 修法 |
| --- | --- | --- |
| 所有 https 目标炸 `ValueError: non-zero flags not allowed in recv() on SSLSocket` | 量首字节用了 `recv(1, MSG_PEEK)`，TLS 不认 flags，且 ValueError 穿过只捕 timeout/OSError 的兜底 | 读出来再回放（`_ReplaySocket`） |
| 中文项目名一进界面就全 0 | 别名塞进 `X-Pta-Project` 头，浏览器构造请求时抛 `non ISO-8859-1` | 非 ASCII 走 `?project=`；后端对头 `unquote` |
| 候选跑了但一条请求没发，却留下 refuted | URL 少 scheme，scope 拒绝后被记成"判定结论" | `/api/run` 直接 400 `bad_url` |
| 图外推的候选永远排不上 | 规则候选足够填满候选池 | `MAX_GRAPH_SLOTS=4` 留尾部位子 |
| 同一接口被当成两个资产 | 证据表 URL 带 `:80`，浏览器抓的不带 | `graph.host_key` 归一并全链路统一 |
| `refers_to` 给出别的主机的 URL | 资源模板用全局集合匹配 | `_resources_by_host` 按主机分组 |
| SQL 注入全判否 | 载荷被"替换"而不是"追加" | `PayloadClass.mode=append` |
| 500 响应带堆栈被判成普通 JSON | 容器负对照盖过强特征 | `CONTAINER_NEG`：强特征命中时不再因外层是 JSON 扣分 |
| 单项目模式下列表空、详情 404 | 台账里没有这条，但工作区存在 | `ProjectBook.fixed_row()` + 启动时 `adopt` |
| 操作台与 CLI 同时开库报锁 | SQLite 默认 busy 超时 0 | `PRAGMA busy_timeout=2000` + `Store.close()` |

---

## 13. 边界与已知限制（诚实清单）

- **没有鉴权**：操作台只监听 `127.0.0.1`，谁连上谁就是 operator。
- **进程内任务**：后台任务是线程（同项目单飞、全局并发 2），进程退出就丢进度，只留最近 20 条进度。
- **不能删项目**：台账只增；`forget` 只把目标移出台账，不动工作区。
- **scope 不可事后编辑**：要改端口/域名就重建 `Scope` 再 `init`——编辑现有 scope 会绕开可复算性。
- **`param_ref` 只看 URL 查询**：`?filter={"user_id":7}` 这种塞在 JSON 字符串里的参数看不见。
- **模型只做补充**：`llm.py` 能补充理由、能否决，不能改判、不能选题。
- **没有公网 OOB 形态**：`oob.py` 依赖本机或自建回连端点。
- **报告只有 HTML/Markdown**，没有 PDF。
- **测试里没有真浏览器**：`browser_nav` 靠替身（`tests/fake_cdp.py`），真机验证要在你本机跑。

---

## 14. 怎么安全地改

### 加一个 oracle（判定器）

1. `src/pta/oracles.py`：写一个类，继承 `Oracle`，实现 `run(self, observations) -> bool`，把中间量写进 `metrics`。
2. `src/pta/vhx.py`：`ORACLE_REGISTRY` 里登记 `"your_name": YourClass`。
3. `tests/test_oracles.py`：至少两条——「命中 → passed 且置信度 ≥0.85」「不命中 → refuted 且不带 title」。

### 加一个模板

1. `src/pta/vhx.py` 的 `TEMPLATES` 加一项：`id / title / side_effect_level / required_fields / preconditions / actions / oracle / threshold`。
2. `actions` 只能从 12 个原语里挑；需要新原语就先在 `executor.py` 实现并补测试。
3. `tests/test_executor.py` 补「有洞 → confirmed / 无洞 → refuted」一对断言（跑在 `MockTransport` 上）。
4. `demo_templates.py` 加一段演示。

### 加一个 CLI 子命令

`src/pta/cli.py`：`rp = sub.add_parser("name")` → 加参数 → `rp.set_defaults(fn=_cmd_name)` → 写 `_cmd_name(args)`。
不要在子命令里直接发请求，一律走 `probe`/`executor`，否则 scope 与审批会被绕过。

### 加一个 API 端点

`src/pta/api.py` 的 GET/POST 分支里加；如果读的是"当前项目"，必须走 `self._project(query)`；
返回形状改了就同步改 `tests/test_api*.py` 与 `UI-HANDOFF.md` 的 §5。

### 改前端

只能改 `src/pta/ui/` 三个文件；不要加构建、不要引外部资源、**不要用 `innerHTML` 拼数据**
（证据正文与 finding title 都来自被扫的站点，属于不可信内容）。详见 `UI-HANDOFF.md`。

---

## 15. 术语表

| 词 | 意思 |
| --- | --- |
| 证据 / evidence | 一对"规范化请求 + 响应体"，用 sha256 寻址，可重算 |
| 观测 / Observation | oracle 看证据时切出来的结构化字段（状态码、body_sha256、样本…） |
| 判定 / Verdict | `passed + confidence + metrics + rationale (+ title)`；只在 oracle 里产生 |
| 结论 / finding | 一条落库的判定，可能被 critic 降级、被人标误报 |
| 候选 / candidate | 还没跑的「模板 + URL + 参数 + 身份 + 优先级 + 理由」 |
| 资产图 | URL 之间的邻接关系，用来外推"同模板换对象/换方法" |
| 通道 | `plain` / `browser` / `curl`，用来分辨"真拒绝"和"被 WAF 拦" |
| 负对照 / decoy | 用来证明"响应确实和这个 id 有关"的对照请求 |
| PTT | 任务树，`--resume` 靠它跳过已完成节点 |
| 审批指纹 | `sha256(tool|host|param_path|payload_class|level)[:24]` |
| 阶段 / stage | 项目级状态：目录不在了 / 已交付 / 待登录态 / 待侦察 / 待判定 / 待复核 / 全是否定 / 可交付 |

---

## 16. 交接清单（给接手的第一天）

- [ ] 跑一遍 `python -m unittest discover -s tests`，确认 846 项 OK
- [ ] 跑 `python demo_run.py`、`python demo_projects.py`、`python live_check.py`
- [ ] `python -m pta.cli ui`，建一个指向**自己的靶场**的项目，走完侦察→候选→跑一轮→交付
- [ ] 读 `README.md`（概览）、本文件（结构）、`UI-HANDOFF.md`（前端契约）三份的顺序别反
- [ ] 换一个真目标之前先看 `scope.json`：`allow_private`、`allowed_ports`、`deny_paths`、`max_requests`
- [ ] 记住：**L2 动作必须自己点**；不确定时先 `--json` 看它打算发什么，再决定
