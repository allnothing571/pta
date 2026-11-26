# PTA P0 — 证据驱动的渗透测试 Agent 骨架

> **授权声明**：本项目仅用于**获得明确授权的**安全测试、自有资产自查与教学靶场。
> 作者不鼓励也不支持对未授权系统使用；使用者自行承担全部合规责任。

只依赖 **Python 3.8 标准库**（有 `cryptography` 则自动启用 AES-256-GCM，否则退化为明文存储并告警）。
所有网络出口只经过 `probe` 一个工具；判定只发生在 oracle 层，别处不许下结论。

- 模板 23 个、oracle 20 个
- 测试 846 项、演示脚本 35 个
- 目标：给自己的授权目标挖洞，从首页走到「可复现的 PoC」

```
从首页开始 → 收资产 → 提候选 → 跑模板 → 出证据 → 判定 → 复核 → 变 PoC → 出报告
```

---

## 快速开始

```bash
# 1. 跑测试（846 项，约 3.5 分钟）
python run_tests.py

# 2. P0 验收（离线 mock 目标，可复现）
python acceptance.py

# 3. P1 执行闭环演示：5 个用例（3 命中 / 2 否定）
python demo_run.py

# 3b. Planner：越权候选/去重/拒答降级/零发散 + 批量 authz 候选
python demo_plan.py

# 3c. Critic：篡改证据 / 同身份配置 / 单证据 / 重放 / 模型否决
python demo_critic.py

# 4. 从一个首页开始（爬取 → 候选 → 图外推 → 诊断）
python demo_discover.py

# 5. 多项目操作台（列表 / 时间线 / 交付 / 后台任务）
python demo_projects.py

# 6. 打开操作台
python -m pta.cli ui                 # http://127.0.0.1:8765/
```

Windows 下先设环境变量：

```powershell
$env:PYTHONPATH='src'
$env:PYTHONIOENCODING='utf-8'
```

---

## 五条不变量

这五条是「能不能信这个结论」的全部依据，任何新功能都不许绕开：

1. **scope 校验在发请求之前**。`Scope.check_request` 是唯一入口，任何工具拿到 URL 之后第一件事就是问它。
2. **预算硬上限**。`max_requests` 是硬账本，不是软提示；续跑（`--resume`）从账本恢复已用额度。
3. **证据可重算**。`evidence_id` = 规范化请求 + 响应体 sha256 的前 24 位，任何人拿到同一对请求/响应都能重算出同一个 id。
4. **L2 及以上动作必须审批**。指纹是 `sha256(tool|host|param_path|payload_class|level)[:24]`，`once` 用后即焚，`class` 带 TTL。
5. **oracle 确定性**。同一份证据喂两遍，结论必须逐字节一致；模型只能补充理由，不能改判。

判定阈值（`verdict_status`）：≥0.85 `confirmed`，≥0.60 `hypothesis`，否则 `refuted`。
凡是 `Verdict(passed=True)`，置信度必须 ≥0.85，否则输出会自相矛盾。

---

## 目录

```
pta-p0/
├─ src/pta/
│  ├─ models.py        领域模型：Scope/Asset/Observation/Verdict/Finding/Extract/Decision
│  ├─ scope.py         白名单校验（域名/端口/方法/路径/私有地址/速率）
│  ├─ transport.py     真 socket 传输：TLS、首字节时间、响应上限、重定向跟随
│  ├─ probe.py         发一次请求 → 一条证据（含通道消歧所需的头部）
│  ├─ store.py         SQLite 账本：证据元数据、结论、动作日志、审批、预算
│  ├─ evidence.py      内容寻址存储（CAS + 主密钥加密），evidence_id 重算
│  ├─ vault.py         凭证保管（cookie / 请求头），按身份隔离
│  ├─ oracles.py       20 个判定器：只看证据，不看请求意图
│  ├─ vhx.py           23 个模板：动作序列 → 载荷类 → oracle
│  ├─ executor.py      执行器：预算、审批、通道、证据落库
│  ├─ runner.py        一轮多候选并发执行 + 断点续跑
│  ├─ planner.py       候选生成：规则 + 资产图 + 写方法识别
│  ├─ graph.py         资产邻接图：五类边（child_resource/sibling_object/refers_to/param_ref/same_resource）
│  ├─ recon.py         爬取：链接、表单、JS 里的接口、落地地址
│  ├─ discover.py      侦察报告 → 候选池 + 诊断
│  ├─ browser.py       CDP 真浏览器（页面自己发的请求）
│  ├─ cdp.py           DevTools 协议最小客户端
│  ├─ harvest.py       Network.* 事件 → 调用形状去重
│  ├─ critic.py        复核：篡改/同身份/单证据/重放
│  ├─ labels.py        人工裁决：标误报、留原判、误报率
│  ├─ poc.py           结论 → 可复现请求（curl/powershell/python/raw）
│  ├─ report.py        报告：单文件 HTML、多轮合并
│  ├─ oob.py           带外（DNS/HTTP 回连）
│  ├─ grants.py        审批预授权：指纹 → 作用域（once/class）
│  ├─ targets.py       目标台账（只记路径与交付，不存结论）
│  ├─ projects.py      多项目：八档阶段、六步时间线、交付、后台任务
│  ├─ api.py           操作台 API（http.server，纯标准库）
│  ├─ ui/              index.html + app.js + style.css（无构建、无 CDN）
│  └─ cli.py           命令行入口
├─ tests/              846 项 unittest
├─ demo_*.py           35 个演示（离线，末行必须是 OK）
├─ live_check.py       真实 socket 冒烟（含 SSRF 带外）
└─ UI-HANDOFF.md       前端交接文档（给做视觉改造的人）
```

---

## 一次真实的目标怎么跑

```powershell
# 1. 建项目（也可以直接用 pta init 建工作区，再在 UI 里收编）
python -m pta.cli init --root D:\work\target --domain example.com --allow-port 443

# 2. 登录态（有登录才需要）
python -m pta.cli auth add --root D:\work\target --identity A --from-curl -
# 然后粘贴浏览器里那条 curl；--cookie-file 也可以

# 3. 侦察：从一个首页开始
python -m pta.cli crawl --root D:\work\target --seed https://example.com/ --max-pages 12 --max-depth 2

# 4. 候选池（含资产图外推）
python -m pta.cli discover --root D:\work\target --seed https://example.com/ --identity A --write

# 5. 跑一条候选
python -m pta.cli run --root D:\work\target --template idor-object-ref `
    --url "https://example.com/api/users/7" --identity-baseline A --identity-probe B

# 6. 看结论 / 变成能直接打的命令
python -m pta.cli show --root D:\work\target --last
python -m pta.cli show --root D:\work\target --last --as powershell

# 7. 出报告
python -m pta.cli report --root D:\work\target --out D:\work\out --html
```

每一步都会落证据；结论只有 `confirmed` / `hypothesis` / `refuted` 三种，`hypothesis` 需要人复核。

---

## 技能清单（按「怎么判」组织）

### 侦察与候选

- **爬取（`crawl`）**：只跟同主机链接，记录 `final_url`（落地地址）与被拦下的重定向；
  从 HTML/JS 里抽接口路径与参数名；跨源一律 skip 并计数（`skipped` 按原因分组）。
- **候选生成（`planner`）**：
  - 规则：`?id=`/`xxx_id` 参数 → idor 候选；写方法（PUT/PATCH/DELETE）→ 写入型候选；
    需要两个身份的接口 → authz 候选。
  - 资产图：五类边，
    `child_resource`（`/api/users/7` → `/api/users`）、
    `sibling_object`（`/api/users/7` → `/api/users/8`）、
    `same_resource`（同路径不同方法）、
    `refers_to`（响应体里出现的 id 指向的资源模板）、
    `param_ref`（URL 查询里带真值的 id 指向的资源模板）。
    跨对象外推只在**本主机内**匹配到资源模板时才连，宁可不连也不造 404 的 URL。
  - 图来源候选优先级低于规则命中（`param_ref` 0.46、`refers_to` 0.42），
    且固定留 4 个位子（`--graph-slots`），否则会被规则候选挤死。
- **`--browser`**：起真 Chrome（CDP），抓页面自己发出的请求，带值的那条进候选池。
  浏览器没走通时只报告原因，不阻断下面的 HTTP 爬取。

### 判定（20 个 oracle）

| 组 | 判什么 | 关键点 |
| --- | --- | --- |
| 注入 | 报错/布尔/时间盲注 | 载荷 `append` 而非 `replace`；时间盲注要过基线与噪声 |
| 越权 | 缺失授权（authz）、IDOR | 两个身份比对；同字节时提示「可能全局共享」 |
| 批量 | 批量未授权读 | 比例分层（0.90/0.86/0.65/0），不看 id 的降级 |
| 写 | 批量赋值、写入型越权、幂等回读 | 判「少了什么」而不是「改成了什么」 |
| 客户端 | 反射型 / 存储型 XSS、CSRF | 存储型要回读；CSRF 摘令牌两态 + 匿名对照 |
| 文件 | 上传、XXE、反序列化 | 上传三档（扩展名/内容类型/解析）；实体绑定 token |
| 网络 | SSRF 打内网、OOB 带外 | 内网地址 + 元数据；带外走 DNS/HTTP 回连 |
| 身份 | JWT 信任边界 | `alg=none`、去签名、算法混淆 |
| 路径 | 路径穿越、开放重定向 | 落地地址与响应体双重确认 |
| 逻辑 | 数字边界、负数金额、数量溢出 | 需要 `expect_value` 回读命中 |
| 竞态 | 并发突发 | 一次占号、固定标记 |
| 信息 | 敏感文件/构建产物/报错页 | 文件签名 + 容器负对照（JSON 里带堆栈也算） |

每条结论都带 `metrics`、`rationale`，敏感文件类还带 `title`（「报错页泄露堆栈（框架/版本/内部路径）」这类）。

### 复核与账本

- **Critic**：篡改证据、同身份配置、单证据、重放、模型否决——任一命中就降级。
- **Labels**：人工标误报，保留原判与可重放坐标；`stats` 给误报率（分母只算人看过的）。
- **Grants**：审批预授权，指纹相同即复用；`audit` 只认日志，不改历史。
- **Targets**：目标台账只记路径、别名与交付状态，不存结论（结论在工作区里）。

### 报告与 PoC

- `show --last --as curl|powershell|python|raw`：从证据直接还原一条可执行请求。
- `report --out DIR --html`：单文件 HTML（内联样式，无外链）；多轮用 `--all` 合并进同一份。

---

## 操作台（P3）

```powershell
python -m pta.cli ui                       # 多项目：读 ~/.pta/targets.json
python -m pta.cli ui --workspace D:\work\target   # 绑死一个工作区
```

三个视图：项目列表（按工作区/阶段筛选）、新建项目（名字 + URL + 工作区，其余按 URL 推）、
项目详情（六步时间线 + 四面板 + 后台任务）。

四个面板只读，不做任何推断：

| 面板 | 读什么 | 能做什么 |
| --- | --- | --- |
| 假设队列 | `/api/state` 的 `findings` + `tally` | 看证据链、复核、跑模板 |
| 资产图 | `/api/state` 的 `evidence`（按 host/path 归并） | 提候选（只展示，不自动执行） |
| 审批栏 | `pending_approvals` | 同意/拒绝，`once` 或 `class`（24h） |
| 证据对比 | `/api/evidence/{a}/diff/{b}` | 选 A/B，双击看原文 |

三个刻意的设计：

1. `/api/run` 是异步的（202 + `run_id`，结论走 SSE），同步等会让浏览器在跑时间盲注时卡住十几秒。
2. 原文要二次确认：`/api/evidence/{id}/raw` 不带 `confirm=1` 一律 403（响应体可能含他人信息）。
3. 对比用 `difflib` 而不是行集合：单行 JSON 只差一个字段时，行集合交集会掉到 0.39，
   而 operator 恰恰要看「几乎一样的两条差在哪」；`SequenceMatcher` 给 0.93。

八档阶段（每次现算，不落库）：目录不在了 / 已交付 / 待登录态 / 待侦察 / 待判定 / 待复核 /
全是否定 / 可交付。交付由人点，`force` 会在备注前留「强制交付：」。

---

## 两个只在真机上才炸的 bug（P3.2）

单测全绿、靶场全绿，第一次拿真实域名跑就连栽两次。两次都不是「判错了」，是**请求没发出去 /
响应没读回来**——没有结论、只有一句异常，所以单独记一笔。

### 一、HTTPS 从来没成功过

```
ValueError: non-zero flags not allowed in calls to recv() on <class 'ssl.SSLSocket'>
```

旧代码为了量首字节时间，用 `sock.recv(1, socket.MSG_PEEK)` 窥视。`socket.socket` 认 flags，
`ssl.SSLSocket` 不认；`MSG_PEEK` 在 TLS 上本来也没有意义（解密后的流没有可窥视的边界）。
更糟的是它抛 `ValueError`，而 `_read_response` 的兜底只捕 `socket.timeout` / `OSError`，
异常直接穿过 probe 打死整轮演练。

修法：**读出来再回放**。

```python
first = sock.recv(1)                                   # 不带 flags
resp = http.client.HTTPResponse(_ReplaySocket(sock, first), method="GET")
```

`_ReplayRaw(io.RawIOBase).readinto` 先把这一字节吐回缓冲区再接真 socket；`_ReplaySocket`
只实现 `HTTPResponse` 唯一用到的方法 `makefile()`。首字节时间仍在 `recv(1)` 之后取。

此前所有靶场（WebGoat、内网 docker、全部 mock）都是明文，所以这一条从未暴露。

### 二、中文项目名进不了 HTTP 头

```
Failed to read the 'headers' property from 'RequestInit': String contains non ISO-8859-1 code point
```

项目名带中文（比如「某某系统」）→ 别名同理 → 塞进 `X-Pta-Project` 头 → 浏览器在**构造请求时**就抛
`TypeError`，一行都没发出去。表现是四个面板全 0、阶段停在「待登录态」：看着像没数据，
其实是没请求。

修法两条：前端只把纯 ASCII 放头，否则走 `?project=` + `encodeURIComponent`；
后端 `_alias()` 对头做 `unquote`（手写 curl 也认）。

教训：凡是「用户输入直接进协议字段」的地方，都要问这个字段的编码边界——
HTTP 头是 latin-1，URL 是 UTF-8 百分号编码，JSON 是 UTF-8，三者不同。

---

## 明确没做（下一批）

- **多用户 / 鉴权**：操作台只监听 `127.0.0.1`，谁连上谁就是 operator。
- **删除项目**：台账只增不删（`pta forget` 只移出台账，不动工作区）。
- **scope 事后编辑**：要改端口/域名就重建 `Scope` 再 `init`，编辑现有 scope 会绕开可复算性。
- **调度器**：后台任务是进程内线程（同项目单飞、全局并发 2），进程退出即丢进度。
- **PDF 报告**：只有单文件 HTML。
- **独立 OOB 服务**：`oob.py` 依赖本地或自建回连端点，没有公网托管形态。
- **模型接入**：P1 的 `--model` 只做「补充理由 / 否决」，没有自动选模板。
- **param_ref 的可见范围**：只认值能直接拼进 URL 的 id；`?filter={"user_id":7}` 这种塞在
  JSON 字符串里的参数看不见。

---

## 验收口径

一个目标算「跑完」，要满足：

1. 从首页开始，不手工喂 URL，候选池里有 ≥5 条带理由的候选；
2. 至少一条 `confirmed`，且 `show --as <shell>` 出来的命令能直接复现；
3. 停下来时，`discover` 的诊断块 / `why` 能说清为什么停（登录态、端口、全是否定、等人审批）。

三条都不满足也算「跑完」，只要它说清了停在哪一步。
