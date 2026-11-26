# UI 交接文档（给设计/前端改造）

> 这份文档只讲**这个操作台前端是什么、和谁对接、哪些不能动、怎么验收**。
> 目标是让接手的人在不读完之后端 8000 行代码的前提下，安全地重做视觉层。
> 仓库根目录：`<repo>`（Python 3.8，纯标准库，无构建链）。

---

## 1. 这是什么

一个**本机单人**的渗透测试操作台：后端是 `pta` 这个 Python 包（扫描/判定/证据），前端是一个静态单页，用来

1. 列项目（每个项目 = 一个工作区目录）、按工作区和阶段筛选、新建项目；
2. 点进一个项目看它走到哪一步（六步时间线 + 一句「为什么停」+ 该点的按钮）；
3. 看这个项目的结论队列、资产、待审批动作、证据对比，并起后台任务（侦察 / 跑一轮 / 出报告）。

用户是安全工程师本人，浏览器只开 `127.0.0.1`，**没有登录、没有多租户**。界面语言是中文。

---

## 2. 怎么跑起来 / 怎么预览

```powershell
cd <repo>
$env:PYTHONPATH='src'
$env:PYTHONIOENCODING='utf-8'

# 多项目模式（认整个台账 ~/.pta/targets.json）
python -m pta.cli ui                 # http://127.0.0.1:8765/

# 绑死一个工作区（列表里只有它，方便反复刷同一个项目）
python -m pta.cli ui --workspace /path/to/ws
```

造一批有数据的假项目（离线、不联网、跑完自动删临时目录）：

```powershell
python demo_projects.py          # 7 段 12 个 check，末行 OK；--serve 可常驻 8766 供真人点
python demo_ui.py --serve        # 单工作区版本的演示数据，常驻 8765
```

改完前端必须重新验证（三条都要绿）：

```powershell
node --check src\pta\ui\app.js                      # JS 语法
python -c "import pta.api"                          # 后端仍能导入
python demo_ui.py ; python demo_projects.py         # 端到端：静态页 + 接口 + 渲染字段
python -m unittest discover -s tests                # 841 项，约 3.5 分钟
```

`tests/test_api_projects.py` 里有一条断言会直接挂掉，如果：

- `/` 返回的 HTML 里没有 `view-projects` 或 `identity-dialog`；
- `/ui/app.js` 里没有 `loadProjects`；
- `/ui/style.css` 里没有 `pcard`。

也就是说：**改样式可以，改这几个名字不行**（改就顺手改测试，见第 7 节）。

---

## 3. 文件地图

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `src/pta/ui/index.html` | 267 | 全部 DOM 结构：topbar + 三个视图 + 四个面板 + 一个抽屉 + 三个 `<dialog>` |
| `src/pta/ui/style.css` | 411 | 全部样式（一个文件，`:root` 里 14 个变量，177 个类选择器） |
| `src/pta/ui/app.js` | 1099 | 全部行为：路由、取数、render*、事件绑定。零依赖 IIFE，`var` 风格，无框架 |
| `src/pta/api.py` | ~880 | 静态页托管（白名单）+ JSON API |
| `src/pta/projects.py` | ~640 | 项目阶段/时间线/交付语义（**只读语义，别改**） |

静态路由是白名单，只有这三个文件能被浏览器拿到：

```
GET /                -> ui/index.html   (text/html)
GET /ui/<name>       -> ui/<name>       (只允许 index.html / app.js / style.css)
其余                  -> 404
```

**不能引入**：第二个 CSS 文件、图片/字体资源、`<script src>` 指向第三方。要加图标就用内联 SVG 或 CSS 画。

---

## 4. 三个视图 + 所有 DOM 契约

`app.js` 全靠 `id` 拿节点。**id 是契约，class 不是。** 可以随便加 class、换 class 名（同时改 JS 里拼 class 的地方和 CSS），但不要改 id。

### 4.1 顶栏 `header.topbar`（三个视图共用）

| id | 内容 | 说明 |
| --- | --- | --- |
| `crumbs` | 面包屑 `<a href="#/">项目</a>` | JS 会往这里追加当前项目名 |
| `eng` | engagement id | 详情页才有意义 |
| `scope-chips` | 域名 / 端口 / 允许内网 / 到期 | 逐个 `<span class="chip">` |
| `bar-req` + `out-req` | 请求预算条与数字 | JS 直接写 `style.width` 和 `className`（`""/warn/danger`） |
| `out-breaker` | 熔断状态 | 非 `closed` 时 JS 写内联 `color` |
| `dot` + `conn-text` | SSE 连接指示 | `dot` 加 class `on`/`off` |

### 4.2 视图 1：项目列表 `#view-projects`

| id | 元素 | 作用 |
| --- | --- | --- |
| `projects-count` | `<span class="count">` | 项目总数 |
| `btn-new` | 按钮 | 跳 `#/new` |
| `pf-q` | `<input type="search">` | 关键词（200ms 防抖） |
| `pf-ws` | `<select>` | 工作区筛选，选项由 JS 重填 |
| `pf-stages` | `<div class="tally">` | 阶段 chips，JS 生成 `<span class="pill [active]">` |
| `pf-hint` | `<div class="mute hintline">` | 台账路径提示 |
| `projects` | `<div class="projects">` | 卡片容器，JS 生成 `.pcard` |

单张卡片的结构（JS 生成，视觉可随便改，**层次不要动**）：

```
.pcard[.ready][.gone]
  .pcard-top   -> .pname + span.pill.stage-<id> + .spacer + .mono.mute(alias)
  .pcard-meta  -> .mono.mute.truncate(root)
  .pcard-counts-> 证据 N / confirmed N(.ok) / hypothesis N(.warn|.mute) / refuted N / 待审批 N(.warn) / 候选 N
  .pcard-why   -> 一句话「为什么停」
```

`.ready` = 可交付（现在只有左边框一条视觉线索，**这里是重点改造位**）。

### 4.3 视图 2：新建项目 `#view-new`

`#new-form`（`.card.form`）里四个字段 + 两个按钮：

`new-name` `new-url` `new-ws` `new-note` `new-hint` `new-submit`。
提交后 201 直接跳详情；409（目录已是项目）时后端回 `{alias}`，前端直接跳到那个项目并提示「已收进台账」。

### 4.4 视图 3：项目详情 `#view-project`

头部：

| id | 作用 |
| --- | --- |
| `p-name` `p-stage` `p-root` | 名字、阶段 pill（JS 会重写 `className = "pill stage-<id>"`）、工作区路径 |
| `p-actions` | 一排按钮，由 `d.next` 生成（见 5.2 的 `next[].kind`） |
| `p-refresh` | 重算阶段 |
| `p-why` | 「为什么停在这儿」一句话（`.why`，空时 CSS 隐藏） |
| `p-steps` | `<ol class="steps">`，六步，每步 `li.step.done|.current|.todo`，内含 `.dotstep` + `.step-label` + `.step-detail` |
| `p-job` | 后台任务行（`hidden` 切换），class `jobline running|done|failed` |

下面是一个 `.grid`，四个面板（**这一层是原来的老界面，结构与 id 全部保留**）：

1. **假设队列**：`findings-count` `btn-critic` `btn-run` `tally` `findings`。
   每条 `.finding` → `.finding-top`（`span.pill.<status>` + `.title` + `.mono.dim` 置信度）、`.finding-meta`（模板中文名 + `.confbar` + 证据条数）、`.finding-why`（rationale）。
2. **资产图**：`assets-count` `btn-plan` `assets` `plan-notes`。按 host 分组，`method + path` 一行。
3. **审批栏**：`approvals-count` `approvals`。每条带同意/拒绝按钮和 `once`/`class` 作用域选择。
4. **证据对比**：`evidence-count` `btn-clear-diff` `ev-filter` `diff-slots` `ev-list` `diff`。选两条 → 后端 `difflib` 比率 → `diffRow` 渲染 `same/chg`。

### 4.5 抽屉与三个 dialog

- `#drawer`（`drawer-title` `drawer-body` `drawer-close`）：展示一条证据的详情，正文要用户点「载入原文」才请求（403 除非 `confirm=1`）。
- `#run-dialog`：`run-template` `run-url` `run-param` `run-method` `run-id-base` `run-id-probe` `run-body` `run-control` `run-submit`。
- `#identity-dialog`：`id-name` `id-cookie` `id-headers`。
- `#recon-dialog`：`recon-seed` `recon-identity` `recon-pages` `recon-depth`。
- `#toasts`：`toast(text, kind)` 往里追加，`kind ∈ ok|warn|err|""`，2.6s 自动移除。

---

## 5. 数据契约（只读，视觉改造不要改这些）

所有请求都会自动带 `X-Pta-Project: <alias>` 头（`setProject()` 写 `localStorage["pta.project"]`）。

### 5.1 `GET /api/projects?workspace=&stage=&q=`

```json
{
  "total": 4,
  "ledger": "<PTA_HOME>/targets.json",
  "workspaces": ["/path/to/labs", "/path/to/clients"],
  "stages": [{"id": "deliverable", "label": "可交付", "count": 1, "inflight": false}, ...8 项],
  "projects": [{
    "alias": "alpha", "name": "alpha", "root": "D:\\labs\\alpha",
    "workspace": "D:\\labs", "engagement_id": "ENG-ALPHA",
    "domains": ["app.test"], "stage": "deliverable", "stage_label": "可交付",
    "deliverable": true, "delivered": false, "delivered_at": null,
    "identity_count": 1,
    "counts": {"evidence": 3, "recon_pages": 1, "confirmed": 1, "hypothesis": 0,
               "refuted": 0, "pending": 0, "candidates": 5},
    "last_activity": "2026-11-13T08:15:05Z", "exists": true, "error": "",
    "why": "1 条 confirmed，没有待审批、也没有未复核的 hypothesis"
  }]
}
```

`counts.candidates` 可能是 `null`（表示「没跑过 discover」），不是 0 —— 现在的卡片用 `!== null` 判断，别丢这个分支。

### 5.2 `GET /api/projects/{alias}`

```json
{
  "stage": "review", "stage_label": "待复核", "deliverable": false,
  "project": { ... 同上 summary ... },
  "steps": [{"id": "identity", "label": "登录态", "state": "done", "detail": "1 个身份：A"}, ...6 项],
  "next": [{"kind": "review", "label": "去复核"}, {"kind": "round", "label": "跑一轮（继续）"}],
  "why": "有结论但还没定下来：1 条 hypothesis 没复核",
  "timeline": [{"ts": "...", "text": "登记进项目台账"}],
  "facts": { ... 原始计数，界面目前不用 ... }
}
```

`steps[].state ∈ done|current|todo`，**只有一个 current**。
`next[].kind ∈ deliver|undeliver|identity|recon|round|report|review`（`doAction` 按 kind 分支，加新 kind 要同时改 JS）。

### 5.3 `POST` 端点

| 路径 | body | 回来 |
| --- | --- | --- |
| `/api/projects` | `{name, url, workspace, note?}` | 201 `{created, project}` / 409 `{error:"already_exists", alias}` / 400 `{error:"bad_name"|"bad_url"|"bad_workspace"}` |
| `/api/projects/{alias}/deliver` | `{delivered: bool, force?: bool, note?}` | 200 `{project, delivered}` / 409 `{error:"not_deliverable", stage, why}` |
| `/api/projects/{alias}/identity` | `{name, cookie?, headers?}` | 200 `{ok, identity, stored:[...]}` |
| `/api/projects/{alias}/recon` | `{seed, identity?, max_pages?, max_depth?}` | 202 `{job}` |
| `/api/projects/{alias}/round` | `{max_rounds?, max_candidates?}` | 202 `{job}` |
| `/api/projects/{alias}/report` | `{out?, html?}` | 202 `{job}` |
| `/api/jobs?project=` | — | `{jobs:[{alias, kind, label, run_id, state, result, error, progress:[]}]}` |

`job.state ∈ queued|running|done|failed`；同项目起第二个任务会 409 `{error:"job_running", job}`。

### 5.4 `GET /api/state`（老四个面板的数据源）

`{engagement, scope{domains, allowed_ports, allow_private, egress_proxy, expires_at}, budget{used,max}, breaker, evidence[最多 60 条], findings[], tally{}, pending_approvals[], templates[], project{alias,name,...}}`

- `evidence[]`: `{evidence_id, method, host, raw_path, status, content_type, label, identity, ts, body_sha256, size}`
- `findings[]`: `{id, template_id, title, status, confidence, evidence_ids[], verdict{metrics{}, rationale, title?}, created_at}`
- `pending_approvals[]`: `{fp, tool, host, param_path, payload_class, level, scope_hint, reason}`

### 5.5 `GET /api/evidence/{a}/diff/{b}`

`{similarity: 0.93, a:{...}, b:{...}, rows:[{key, a, b, kind:"same"|"chg"}]}` —— `similarity` 用 `difflib` 算，不是行集合交集。

---

## 6. CSS 现状（可以整段替换）

```css
:root {
  --bg:#0d1117; --bg-2:#131a23; --bg-3:#1a232e;
  --line:#24303d; --line-2:#31404f;
  --fg:#d7e0ea; --fg-dim:#8b9aab; --fg-mute:#5f6f80;
  --accent:#7ee787; --accent-dim:#2f6b3a;
  --warn:#f0b72f; --danger:#ff6b6b; --info:#6fb3ff;
  --mono: ui-monospace, "Cascadia Mono", "JetBrains Mono", Consolas, monospace;
}
```

颜色是有语义的，别只按好看重排（`confirmed` 永远绿、`hypothesis` 永远黄、`refuted` 灰、`missing/危险` 红）：

| 语义 | 变量 / 现在值 |
| --- | --- |
| 已确认 / 可交付 / 预算健康 | `--accent` |
| 待验证 / 待审批 / 预算 70%+ | `--warn` |
| 已否定 / 已交付 / 次要说明 | `--fg-mute` |
| 目录不在了 / 预算 90%+ / 危险操作 | `--danger` |
| 链接 / 信息 / 外带 | `--info` |

类大致分四组（共 177 个选择器）：布局（`topbar grid panel view steps projects pcard*`）、控件（`btn sm primary ghost danger pill chip tally field pair`）、内容（`finding* asset ev* diff* drawer*`）、状态（`ok warn danger mute dim active ready gone done current`）。列表见 `src/pta/ui/style.css` 头部注释。

现有字号偏小（11–13px），密度偏高——这是历史选择（一屏塞更多证据），**可以重排，但要保证一屏仍能看下 8–10 条 finding**。

---

## 7. 硬约束（改了就坏）

1. **不能引入构建步骤**：没有 npm、没有打包器、没有 PostCSS。CSS/JS 必须是浏览器直接能吃的形式。
2. **不能引入外部资源**：CDN、Google Fonts、图标库、图片文件都不行（离线可用是需求）。图标用内联 SVG。
3. **不能改 URL 路由**：`#/`、`#/new`、`#/p/<alias>` 是 `route()` 硬编码的，也是用户书签。
4. **不能改 `localStorage["pta.project"]`** 这个键名。
5. **不能改 id**（第 4 节那批），也不要改 `STATUS_CN`/`METRIC_CN`/`STAGE_CN`/`TEMPLATE_CN` 的键名（中文值可以润色）。
6. **不要用 `innerHTML` 拼数据**：现在所有文本都走 `el(tag, cls, text)` → `textContent`。证据原文、findings 的 title 都是**不可信内容**（来自被扫的站点），拼 HTML 就是自造 XSS。要改结构就用 `createElement`。
7. **不要改后端的响应形状**（`src/pta/api.py` / `projects.py`）。要显示新字段，先确认 `state_payload` 里有；没有就单独提，不要在前端猜。
8. **不能给 `/ui/` 之外的路径加静态文件**：`STATIC_FILES` 白名单在 `src/pta/api.py:37`，加文件要同时改白名单和 `tests/test_api_projects.py::test_static_shell_is_served`。
9. **不要动 `deliver` 的二次确认语义**：不可交付时 409 → 前端 `window.confirm` → `force:true`。这是「人来做决定」的落点。
10. **保持中文**：所有面向用户的文案是中文，数字/URL/路径用 `--mono`。

---

## 8. 可以放心改的（这次想要的就是这些）

- 视觉语言整体重做：配色、层次、圆角/描边、阴影、间距节奏、字体栈（用系统字体，别下载）。
- `.pcard` 的信息层次与「可交付」的强调方式（现在是左边框一条线，太弱）。
- 阶段 pill 的色阶（8 档现在只靠 4 个颜色区分）。
- 六步时间线的形态（现在是竖排圆点列表，信息密度低、占地方）。
- 顶部 topbar：预算条、scope chips、SSE 指示灯的表达。
- 空态（现在是一行灰字）、加载态（现在没有骨架屏）、错误态（现在是一行红字）。
- 抽屉与 dialog 的版式（现在是浏览器默认 `dialog`）。
- 响应式：现在没有断点，窄屏时 `.grid` 会挤成一条；建议 ≤1100px 单列。
- 可访问性：`focus-visible` 样式、`aria-*`、tab 顺序、`prefers-reduced-motion`（现在有 transition 但没有降级）。
- 证据对比的 diff 视觉（现在靠 `.same/.chg` 两种底色）。

**先问再动的**：新增端点 / 新增字段 / 改变任务启动语义 / 改交付流程 / 增加新的视图路由。

---

## 9. 已知的粗糙点（供改造时参考）

1. 字号 11–13px，长时间看累；但密度是刻意的。
2. `.pcard` 里 `why` 文案会被截断到一行（靠 `truncate`），长句子看不全。
3. `#p-steps` 六步在窄屏会换行错位。
4. 顶部 `bar-req` 是纯色块，没有刻度；`out-breaker` 只有文字。
5. `.finding` 卡片点击整块开抽屉，但 hover 反馈只有一个背景变化。
6. 项目列表没有「最近活动」时间显示（数据里有 `last_activity`，界面没用）。
7. `toast` 固定在右下，三条以上会叠在一起。
8. 三个 dialog 宽度固定 520px，长 placeholder 会溢出。
9. `#drawer` 宽度固定 520px，JSON 正文横向滚动。
10. 没有 dark/light 切换（只有深色），也没有主题变量层。

---

## 10. 一句话总结给接手的人

> 后端只给 JSON，页面是「一个 HTML + 一个 CSS + 一个 JS」，所有节点靠 id 挂载、所有文本靠 `textContent` 写入。
> **改样式随便改，改 id / 路由 / 数据形状 / 引入构建工具会直接挂测试。**
