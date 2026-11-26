/* PTA P0 操作台。零依赖：只用 fetch / EventSource / DOM。
 * 原则：所有服务端数据一律走 textContent 渲染，绝不拼 innerHTML ——
 * 证据里可能带着目标回显的 HTML，那是不可信内容。 */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  var state = null;
  var filterStatus = "all";
  var selA = null, selB = null;
  var evFilter = "";

  // 当前项目。所有请求都带 X-Pta-Project，服务端不认识就 404——
  // 不做「猜一个项目」，猜错会把别人的证据画到这一页上。
  var project = "";
  try { project = localStorage.getItem("pta.project") || ""; } catch (e) { project = ""; }
  var view = "";            // projects / new / project
  var pfStage = "";         // 列表的阶段筛选："inflight" 或 STAGES 里的 id
  var pfWorkspace = "";
  var pDetail = null;       // 详情缓存：steps / next / facts
  var jobTimer = null;
  var listRequest = 0;
  var sidebarReturn = null;

  function setProject(alias) {
    project = alias || "";
    try {
      if (project) localStorage.setItem("pta.project", project);
      else localStorage.removeItem("pta.project");
    } catch (e) { /* 隐私模式下 localStorage 会抛，忽略 */ }
  }

  // ---------- API ----------
  function api(path, opts) {
    opts = opts || {};
    var headers = opts.headers || {};
    // HTTP 头只能放 ISO-8859-1；项目名/别名可能是中文，那种身份走 query（URL 会自己转义）。
    if (project) {
      if (/^[\x20-\x7e]*$/.test(project)) {
        headers["X-Pta-Project"] = project;
      } else {
        path += (path.indexOf("?") >= 0 ? "&" : "?") + "project=" + encodeURIComponent(project);
      }
    }
    opts.headers = headers;
    return fetch(path, opts).then(function (r) {
      return r.text().then(function (t) {
        var data = null;
        try { data = t ? JSON.parse(t) : null; } catch (e) { data = null; }
        if (!r.ok) {
          var msg = (data && (data.message || data.error || data.reason)) || ("HTTP " + r.status);
          var err = new Error(msg);
          err.status = r.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  function post(path, body) {
    return api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    });
  }

  // ---------- toast ----------
  function toast(text, kind) {
    var box = $("#toasts");
    var t = el("div", "toast" + (kind ? " " + kind : ""));
    t.appendChild(el("div", null, text));
    t.appendChild(el("div", "t", new Date().toLocaleTimeString()));
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, 6000);
  }

  // ---------- 顶栏 ----------
  function renderHeader(s) {
    $("#eng").textContent = s.engagement || "—";
    var chips = $("#scope-chips");
    chips.textContent = "";
    (s.scope.domains || []).forEach(function (d) { chips.appendChild(el("span", "chip", d)); });
    if (s.scope.egress_proxy) chips.appendChild(el("span", "chip", "代理 " + s.scope.egress_proxy));
    if (s.scope.allow_private) chips.appendChild(el("span", "chip", "允许内网"));
    (s.scope.allowed_ports || []).forEach(function (p) {
      if (p !== 80 && p !== 443) chips.appendChild(el("span", "chip", ":" + p));
    });
    var exp = s.scope.expires_at || (s.engagement_detail && s.engagement_detail.expires_at);
    if (exp) chips.appendChild(el("span", "chip", "到期 " + exp));

    var used = s.budget.used || 0, max = s.budget.max || 1;
    var pct = Math.min(100, Math.round(used * 100 / max));
    var bar = $("#bar-req");
    bar.style.width = pct + "%";
    bar.className = pct >= 90 ? "danger" : (pct >= 70 ? "warn" : "");
    $("#out-req").textContent = used + " / " + max;

    var br = s.budget.breaker || "closed";
    var ob = $("#out-breaker");
    ob.textContent = br === "closed" ? "正常" : br;
    ob.style.color = br === "closed" ? "" : "var(--warn)";
  }

  // ---------- 假设队列 ----------
  var STATUS_CN = {
    confirmed: "已确认",
    hypothesis: "待验证",
    refuted: "已否定",
    pending_approval: "待审批"
  };
  // 判定指标的键来自各 oracle 的 metrics，界面上要能一眼读懂，
  // 所以这里做中文名 + 单位；没登记的键原样显示（不猜语义）。
  var METRIC_CN = {
    jaccard: "内容重合度", len_ratio: "长度比", similarity: "相似度",
    threshold: "阈值", min_similarity: "阈值", min_delta: "最小抬升级数",
    baseline_rank: "基线权限级", probe_rank: "注入后权限级", delta: "权限级差",
    status_baseline: "基线状态码", status_probe: "注入后状态码",
    baseline_samples: "基线样本数", probe_samples: "注入样本数",
    warmup_dropped: "丢弃的冷启动样本", zero_baseline: "基线 0ms 样本",
    zero_probe: "注入 0ms 样本", p_value: "p 值", alpha: "显著性阈值",
    effect_ms: "中位延时差", baseline_median_ms: "基线中位耗时",
    probe_median_ms: "注入中位耗时", cv_baseline: "基线离散度",
    cv_probe: "注入离散度", noise_allowance_ms: "噪声允许量",
    spread_baseline_ms: "基线采样跨度", spread_probe_ms: "注入采样跨度",
    requests: "请求数", pairs: "配对数"
  };

  function metricText(key, v) {
    if (typeof v !== "number") return String(v);
    if (/_ms$/.test(key)) return v.toFixed(1) + " ms";
    if (key === "p_value") return v.toFixed(4);
    if (key === "alpha" || /^cv_/.test(key) || key === "jaccard" || key === "len_ratio" ||
        key === "similarity" || key === "threshold" || key === "min_similarity") {
      return v.toFixed(3);
    }
    return String(v);
  }

  var TEMPLATE_CN = {
    "idor-object-ref": "越权读对象",
    "authz-missing-endpoint": "接口缺失授权",
    "sqli-error-boolean": "报错型 SQL 注入",
    "sqli-boolean-blind": "布尔盲注",
  "idor-write-object": "写入越权",
  "ssrf-internal-service": "SSRF 打内网",
    "sqli-time-blind": "时间盲注",
    "xss-reflected": "反射型 XSS",
    "ssrf-outbound": "带外 SSRF",
    "open-redirect": "开放重定向",
    "info-disclosure-artifact": "配置文件暴露",
    "jwt-trust-boundary": "JWT 信任边界",
    "mass-assignment-privilege": "批量赋值提权",
    "path-traversal-lfi": "路径穿越 / 文件读"
  };

  function confBar(f) {
    var wrap = el("div", "confbar");
    var i = el("i", f.status);
    i.style.width = Math.round((f.confidence || 0) * 100) + "%";
    wrap.appendChild(i);
    return wrap;
  }

  function renderFindings(s) {
    var box = $("#findings");
    box.textContent = "";
    $("#findings-count").textContent = String(s.findings.length);

    var counts = { confirmed: 0, hypothesis: 0, refuted: 0, pending_approval: 0 };
    s.findings.forEach(function (f) { counts[f.status] = (counts[f.status] || 0) + 1; });

    var tally = $("#tally");
    tally.textContent = "";
    tally.appendChild(tallyChip("all", "全部 " + s.findings.length));
    Object.keys(counts).forEach(function (k) {
      tally.appendChild(tallyChip(k, STATUS_CN[k] + " " + counts[k]));
    });

    var rows = s.findings.filter(function (f) {
      return filterStatus === "all" || f.status === filterStatus;
    });
    if (!rows.length) {
      box.appendChild(el("div", "empty", s.findings.length ? "这个状态下没有 finding" : "还没有 finding：先跑模板，或让 Planner 提候选"));
      return;
    }
    rows.slice().reverse().forEach(function (f) {
      var card = el("div", "finding");
      var top = el("div", "finding-top");
      top.appendChild(el("span", "pill " + f.status, STATUS_CN[f.status] || f.status));
      top.appendChild(el("span", "title truncate", f.title || f.template_id));
      var conf = el("span", "mono dim", (f.confidence || 0).toFixed(3));
      conf.style.marginLeft = "auto";
      top.appendChild(conf);
      card.appendChild(top);

      var meta = el("div", "finding-meta");
      meta.appendChild(el("span", "mute", TEMPLATE_CN[f.template_id] || f.template_id));
      meta.appendChild(confBar(f));
      meta.appendChild(el("span", "mute", (f.evidence_ids || []).length + " 证据"));
      card.appendChild(meta);

      if (f.rationale) card.appendChild(el("div", "finding-why", f.rationale));
      card.addEventListener("click", function () { openFinding(f); });
      box.appendChild(card);
    });
  }

  function tallyChip(key, label) {
    var c = el("span", "pill" + (filterStatus === key ? " active" : ""), label);
    c.addEventListener("click", function () { filterStatus = key; renderFindings(state); });
    return c;
  }

  // ---------- 资产图 ----------
  function buildAssets(evidence) {
    var hosts = {};
    evidence.forEach(function (e) {
      var h = hosts[e.host] || (hosts[e.host] = { host: e.host, paths: {}, total: 0 });
      var k = e.method + " " + e.raw_path;
      var p = h.paths[k] || (h.paths[k] = {
        method: e.method, path: e.raw_path, statuses: {}, hits: 0,
        labels: {}, last: e.evidence_id
      });
      p.hits += 1;
      p.statuses[e.status] = (p.statuses[e.status] || 0) + 1;
      p.labels[e.label] = true;
      p.last = e.evidence_id;
      h.total += 1;
    });
    return hosts;
  }

  function renderAssets(s) {
    var box = $("#assets");
    box.textContent = "";
    var hosts = buildAssets(s.evidence);
    var names = Object.keys(hosts);
    $("#assets-count").textContent = names.length + " 主机 / " + s.evidence.length + " 证据";
    if (!names.length) {
      box.appendChild(el("div", "empty", "还没有证据：资产图从证据表长出来"));
      return;
    }
    names.sort().forEach(function (h) {
      var host = hosts[h];
      var wrap = el("div", "host");
      var head = el("div", "host-head");
      head.appendChild(el("span", null, host.host));
      head.appendChild(el("span", "mute", Object.keys(host.paths).length + " 端点"));
      head.appendChild(el("span", "mute", host.total + " 证据"));
      wrap.appendChild(head);

      Object.keys(host.paths).sort().forEach(function (k) {
        var p = host.paths[k];
        var row = el("div", "asset");
        row.appendChild(el("span", "mute", p.method));
        row.appendChild(el("span", "path truncate", p.path));
        var codes = Object.keys(p.statuses).sort();
        var st = el("span", "st " + (codes.length === 1 && codes[0] === "200" ? "ok" : "err"),
          codes.join("/"));
        row.appendChild(st);
        row.appendChild(el("span", "mute", "×" + p.hits));
        row.appendChild(el("span", "mute truncate", Object.keys(p.labels).join(",")));
        row.addEventListener("click", function () {
          evFilter = p.path;
          $("#ev-filter").value = p.path;
          renderEvidence(state);
        });
        wrap.appendChild(row);
      });
      box.appendChild(wrap);
    });
  }

  // ---------- 审批 ----------
  function renderApprovals(s) {
    var box = $("#approvals");
    box.textContent = "";
    var list = s.pending_approvals || [];
    $("#approvals-count").textContent = String(list.length);
    $("#nav-approvals").textContent = String(list.length);
    if (!list.length) {
      box.appendChild(el("div", "empty", "没有待审批动作：L0/L1 自动放行，L2 才需要你点头"));
      return;
    }
    list.forEach(function (a) {
      var card = el("div", "approval");
      var top = el("div", "approval-top");
      top.appendChild(el("span", "pill " + (a.level || "L2"), a.level || "L2"));
      top.appendChild(el("span", "mono", a.host || "?"));
      top.appendChild(el("span", "mute", (a.param_path || "-") + " · " + (a.payload_class || "-")));
      var fp = el("span", "fp", a.fp.slice(0, 10));
      fp.style.marginLeft = "auto";
      fp.title = a.fp;
      top.appendChild(fp);
      card.appendChild(top);
      card.appendChild(el("div", "why", a.reason || ""));
      if (a.url) card.appendChild(el("div", "url", a.url));

      var acts = el("div", "acts");
      acts.appendChild(actBtn("同意一次", "primary", function () { decide(a.fp, "approve", "once"); }));
      acts.appendChild(actBtn("同意此类 24h", "", function () { decide(a.fp, "approve", "class"); }));
      acts.appendChild(actBtn("拒绝", "danger", function () { decide(a.fp, "reject", "once"); }));
      acts.appendChild(actBtn("加备注拒绝", "ghost", function () {
        var note = window.prompt("拒绝理由（会写进审计日志）", "");
        if (note === null) return;
        decide(a.fp, "reject", "once", note);
      }));
      card.appendChild(acts);
      box.appendChild(card);
    });
  }

  function actBtn(label, kind, fn) {
    var b = el("button", "btn sm" + (kind ? " " + kind : ""), label);
    b.type = "button";
    b.addEventListener("click", function () {
      b.disabled = true;
      Promise.resolve(fn()).catch(function (e) { toast("操作失败：" + e.message, "err"); })
        .then(function () { b.disabled = false; });
    });
    return b;
  }

  function decide(fp, decision, scope, note) {
    return post("/api/approvals/" + encodeURIComponent(fp) + "/decide",
      { decision: decision, scope: scope, note: note || "" })
      .then(function () {
        toast((decision === "approve" ? "已放行" : "已拒绝") + "（" + (scope === "class" ? "同类 24h" : "仅本次") + "）",
          decision === "approve" ? "" : "warn");
        return refresh();
      });
  }

  // ---------- 证据列表 ----------
  // 两个对比槽：A/B 各自显示"谁"，空槽显示提示；点 × 清掉这一个。
  // 早先挤成一行文本 "A xxxxxxxx · B —"，窄屏直接被裁掉只剩一个字。
  function renderSlots() {
    var box = $("#diff-slots");
    box.textContent = "";
    [["A", selA], ["B", selB]].forEach(function (pair) {
      var id = pair[1];
      var meta = null;
      (state.evidence || []).forEach(function (e) { if (e.evidence_id === id) meta = e; });
      var chip = el("span", "slot-chip" + (id ? " on" : ""));
      chip.appendChild(el("b", null, pair[0]));
      chip.appendChild(el("span", "path", meta
        ? meta.method + " " + meta.raw_path
        : "点上方证据选入"));
      if (id) {
        var x = el("button", "x", "×");
        x.title = "清空这个槽";
        x.addEventListener("click", function (ev) {
          ev.stopPropagation();
          if (pair[0] === "A") { selA = null; } else { selB = null; }
          renderEvidence(state);
          renderDiff();
        });
        chip.appendChild(x);
      }
      box.appendChild(chip);
    });
  }

  function renderEvidence(s) {
    var box = $("#ev-list");
    box.textContent = "";
    $("#evidence-count").textContent = s.evidence_count + (s.evidence_count > s.evidence.length ? "（显示最近 " + s.evidence.length + "）" : "");
    renderSlots();

    var rows = s.evidence.filter(function (e) {
      if (!evFilter) return true;
      var hay = (e.label + " " + e.host + " " + e.raw_path + " " + e.status + " " + e.identity).toLowerCase();
      return hay.indexOf(evFilter.toLowerCase()) >= 0;
    });
    if (!rows.length) {
      box.appendChild(el("div", "empty", evFilter ? "没有匹配的证据" : "还没有证据"));
      return;
    }
    rows.slice().reverse().forEach(function (e) {
      var row = el("div", "ev" + (e.evidence_id === selA || e.evidence_id === selB ? " on" : ""));
      var slot = e.evidence_id === selA ? "A" : (e.evidence_id === selB ? "B" : "");
      row.appendChild(el("span", "slot", slot));
      row.appendChild(el("span", "mute", e.status));
      row.appendChild(el("span", "lbl", e.label + "  " + e.method + " " + e.raw_path));
      row.appendChild(el("span", "mute", e.samples > 1 ? "×" + e.samples : ""));

      row.addEventListener("click", function (ev) {
        if (ev.shiftKey) { openEvidence(e.evidence_id); return; }
        if (e.evidence_id === selA) { selA = null; }
        else if (e.evidence_id === selB) { selB = null; }
        else if (!selA) { selA = e.evidence_id; }
        else if (!selB) { selB = e.evidence_id; }
        else { selA = selB; selB = e.evidence_id; }
        renderEvidence(state);
        renderDiff();
      });
      row.addEventListener("dblclick", function () { openEvidence(e.evidence_id); });
      box.appendChild(row);
    });
  }

  function renderDiff() {
    var box = $("#diff");
    box.textContent = "";
    if (!selA || !selB) {
      box.appendChild(el("div", "empty", "选两条证据（A / B）看差异；双击单条看完整证据"));
      return;
    }
    box.appendChild(el("div", "mute", "加载对比…"));
    api("/api/evidence/" + encodeURIComponent(selA) + "/diff/" + encodeURIComponent(selB))
      .then(function (d) {
        box.textContent = "";
        var wrap = el("div", "diff");
        wrap.appendChild(diffRow("URL", d.a.method + " " + d.a.host + d.a.raw_path + "  /  " +
          d.b.method + " " + d.b.host + d.b.raw_path, d.same_url ? "same" : "chg"));
        wrap.appendChild(diffRow("状态码", d.a.status + " → " + d.b.status, d.a.status === d.b.status ? "same" : "chg"));
        wrap.appendChild(diffRow("身份", (d.a.identity || "-") + " → " + (d.b.identity || "-"),
          d.a.identity === d.b.identity ? "same" : "chg"));
        wrap.appendChild(diffRow("body 长度", d.a.body_len + " → " + d.b.body_len,
          d.a.body_len === d.b.body_len ? "same" : "chg"));
        wrap.appendChild(diffRow("body 哈希", d.body_same ? "一致" : "不同", d.body_same ? "same" : "bad"));
        wrap.appendChild(diffRow("相似度", (d.similarity * 100).toFixed(1) + "%",
          d.similarity >= 0.9 ? "same" : (d.similarity >= 0.6 ? "chg" : "bad")));
        if (d.header_changes && d.header_changes.length) {
          wrap.appendChild(diffRow("头变化", d.header_changes.join("；"), "chg"));
        }
        wrap.appendChild(el("div", "mute", "A 预览"));
        wrap.appendChild(el("pre", null, d.a.body_preview || "（空）"));
        wrap.appendChild(el("div", "mute", "B 预览"));
        wrap.appendChild(el("pre", null, d.b.body_preview || "（空）"));
        box.appendChild(wrap);
      })
      .catch(function (e) { box.textContent = ""; box.appendChild(el("div", "empty", "对比失败：" + e.message)); });
  }

  function diffRow(k, v, cls) {
    var row = el("div", "row");
    row.appendChild(el("span", "k", k));
    row.appendChild(el("span", cls || "", v));
    return row;
  }

  // ---------- 证据抽屉 ----------
  function openEvidence(id) {
    var d = $("#drawer");
    $("#drawer-title").textContent = "证据 " + id.slice(0, 12);
    var body = $("#drawer-body");
    body.textContent = "";
    body.appendChild(el("div", "mute", "加载中…"));
    d.classList.add("open");
    api("/api/evidence/" + encodeURIComponent(id)).then(function (e) {
      body.textContent = "";
      var dl = el("dl", "kv");
      kv(dl, "label", e.label);
      kv(dl, "身份", e.identity || "none");
      kv(dl, "请求", e.method + " " + e.host + (e.port && e.port !== 80 && e.port !== 443 ? ":" + e.port : "") + e.raw_path);
      kv(dl, "状态", e.status);
      kv(dl, "类型", e.content_type || "-");
      kv(dl, "样本", e.sample_count + " 次");
      kv(dl, "耗时", (e.timings || []).map(function (t) { return t.toFixed(1); }).join(" / ") + " ms");
      kv(dl, "长度", e.body_len + " 字节");
      kv(dl, "sha256", e.body_sha256);
      body.appendChild(dl);

      body.appendChild(el("div", "mute", "响应头"));
      body.appendChild(el("pre", null, (e.headers || []).map(function (h) { return h[0] + ": " + h[1]; }).join("\n") || "（无）"));

      body.appendChild(el("div", "mute", "body 预览（前 4000 字符，已按 UTF-8 解码）"));
      body.appendChild(el("pre", null, e.body_preview || "（空）"));

      var acts = el("div", "acts");
      var raw = el("a", "btn sm", "打开原始字节");
      raw.href = "/api/evidence/" + encodeURIComponent(id) + "/raw?confirm=1";
      raw.target = "_blank";
      raw.rel = "noopener";
      acts.appendChild(raw);
      var copy = el("button", "btn sm ghost", "复制 sha256");
      copy.addEventListener("click", function () {
        navigator.clipboard && navigator.clipboard.writeText(e.body_sha256);
        toast("已复制 sha256");
      });
      acts.appendChild(copy);
      body.appendChild(acts);
      body.appendChild(el("div", "mute", "原始字节以 text/plain 返回，并带 nosniff + CSP，避免把目标回显当成页面执行。"));
    }).catch(function (err) {
      body.textContent = "";
      body.appendChild(el("div", "empty", "读取失败：" + err.message));
    });
  }

  function kv(dl, k, v) {
    dl.appendChild(el("dt", null, k));
    dl.appendChild(el("dd", null, v === undefined || v === null ? "-" : v));
  }

  function openFinding(f) {
    var d = $("#drawer");
    $("#drawer-title").textContent = f.title || f.template_id;
    var body = $("#drawer-body");
    body.textContent = "";
    var dl = el("dl", "kv");
    kv(dl, "模板", (TEMPLATE_CN[f.template_id] || f.template_id) + "（" + f.template_id + "）");
    kv(dl, "状态", STATUS_CN[f.status] || f.status);
    kv(dl, "置信度", (f.confidence || 0).toFixed(3));
    kv(dl, "理由", f.rationale || "-");
    body.appendChild(dl);

    if (f.metrics && Object.keys(f.metrics).length) {
      body.appendChild(el("div", "mute", "判定指标"));
      var mk = el("dl", "kv");
      Object.keys(f.metrics).forEach(function (k) {
        kv(mk, METRIC_CN[k] || k, metricText(k, f.metrics[k]));
      });
      body.appendChild(mk);
    }

    body.appendChild(el("div", "mute", "证据链"));
    var chain = el("div", "ev-chain");
    (f.evidence_ids || []).forEach(function (id, i) {
      var item = el("div", "chain-item");
      item.appendChild(el("span", "arrow", i ? "→" : "•"));
      var b = el("button", "btn sm ghost mono", id.slice(0, 16));
      b.addEventListener("click", function () { openEvidence(id); });
      item.appendChild(b);
      chain.appendChild(item);
    });
    if (!(f.evidence_ids || []).length) chain.appendChild(el("div", "mute", "（无证据，说明没跑起来）"));
    body.appendChild(chain);

    body.appendChild(el("div", "mute", "一票否决"));
    var acts = el("div", "acts");
    ["refuted", "hypothesis", "confirmed"].forEach(function (s) {
      acts.appendChild(actBtn("改为 " + STATUS_CN[s], s === "refuted" ? "danger" : "", function () {
        return post("/api/findings/" + encodeURIComponent(f.id) + "/override",
          { status: s, note: "operator override via UI" })
          .then(function () { toast("已改为 " + STATUS_CN[s]); d.classList.remove("open"); return refresh(); });
      }));
    });
    body.appendChild(acts);
    d.classList.add("open");
  }

  // ---------- 跑模板 ----------
  function openRunDialog(prefill) {
    var sel = $("#run-template");
    sel.textContent = "";
    (state.templates || []).forEach(function (t) {
      var o = el("option", null, (TEMPLATE_CN[t.id] || t.title) + "  [" + t.side_effect_level + "]");
      o.value = t.id;
      sel.appendChild(o);
    });
    var p = prefill || {};
    if (p.template_id) sel.value = p.template_id;
    if (p.url) $("#run-url").value = p.url;
    $("#run-param").value = p.param_path || "";
    if (p.method) $("#run-method").value = p.method;
    $("#run-id-base").value = p.identity_baseline || "none";
    $("#run-id-probe").value = p.identity_probe || "none";
    $("#run-control").value = p.control_url || "";
    var dlg = $("#run-dialog");
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute("open", "");
  }

  function submitRun(ev) {
    ev.preventDefault();
    var body = {
      template: $("#run-template").value,
      url: $("#run-url").value.trim(),
      param_path: $("#run-param").value.trim() || null,
      method: $("#run-method").value,
      identity_baseline: $("#run-id-base").value.trim() || "none",
      identity_probe: $("#run-id-probe").value.trim() || "none",
      control_url: $("#run-control").value.trim() || null
    };
    var raw = $("#run-body").value.trim();
    if (raw) {
      try { body.body_json = JSON.parse(raw); }
      catch (e) { toast("请求体不是合法 JSON", "err"); return; }
    }
    var btn = $("#run-submit");
    btn.disabled = true;
    btn.textContent = "运行中…";
    post("/api/run", body).then(function (r) {
      toast("已提交：run " + (r.run_id || "").slice(0, 8) + "（L2 会先进审批栏）");
      $("#run-dialog").close();
    }).catch(function (e) {
      toast("提交失败：" + e.message, "err");
    }).then(function () {
      btn.disabled = false;
      btn.textContent = "开始";
    });
  }

  // ---------- 项目：路由与三个视图 ----------
  var STAGE_CN = {
    missing: "工作区不在了", delivered: "已交付", no_identity: "待登录态",
    no_recon: "待侦察", no_verdict: "待判定", review: "待复核",
    no_confirmed: "判完无真结论", deliverable: "可交付"
  };

  function setView(name) {
    view = name;
    [["view-projects", "projects"], ["view-new", "new"], ["view-project", "project"]]
      .forEach(function (pair) {
        var n = document.getElementById(pair[0]);
        if (n) n.hidden = pair[1] !== name;
      });
    document.body.className = "view-" + name;
    $("#project-nav").hidden = name !== "project";
    setSidebar(false);
    if (name === "project") selectPanel("p-name");
  }

  function route() {
    var h = (location.hash || "#/").replace(/^#/, "") || "/";
    if (h === "/new") {
      setView("new");
      setProject("");
      document.getElementById("eng").textContent = "—";
      document.getElementById("scope-chips").textContent = "";
      var nameInput = document.getElementById("new-name");
      if (nameInput) nameInput.focus();
      loadNavigation();
      return;
    }
    var m = h.match(/^\/p\/(.+)$/);
    if (m) {
      var alias = decodeURIComponent(m[1]);
      setProject(alias);
      setView("project");
      loadProject(alias);
      refresh();
      loadNavigation();
      return;
    }
    setView("projects");
    setProject("");
    document.getElementById("eng").textContent = "—";
    document.getElementById("scope-chips").textContent = "";
    loadProjects();
  }

  function go(hash) {
    if (location.hash === hash) route();
    else location.hash = hash;
  }

  // ---------- 列表 ----------
  function loadProjects() {
    var request = ++listRequest;
    var qs = [];
    if (pfWorkspace) qs.push("workspace=" + encodeURIComponent(pfWorkspace));
    if (pfStage) qs.push("stage=" + encodeURIComponent(pfStage));
    var q = document.getElementById("pf-q").value.trim();
    if (q) qs.push("q=" + encodeURIComponent(q));
    var box = $("#projects");
    box.setAttribute("aria-busy", "true");
    if (!box.children.length) {
      for (var i = 0; i < 3; i++) box.appendChild(el("div", "loading-row"));
    }
    api("/api/projects" + (qs.length ? "?" + qs.join("&") : ""))
      .then(function (d) {
        if (request !== listRequest || view !== "projects") return;
        box.setAttribute("aria-busy", "false");
        renderProjects(d);
      })
      .catch(function (e) {
        if (request !== listRequest || view !== "projects") return;
        box.setAttribute("aria-busy", "false");
        listState("读取项目失败", e.message, "重新加载", loadProjects, true);
      });
  }

  function renderProjects(d) {
    document.getElementById("projects-count").textContent = String(d.total || 0);

    renderNavigation(d);
    var titles = { inflight: "进行中", review: "待复核", deliverable: "可交付", delivered: "已交付" };
    $("#project-list-title").textContent = titles[pfStage] || STAGE_CN[pfStage] || "全部项目";
    $("#projects-subtitle").textContent = "查看项目阶段、结论和最近活动。";
    $("#filter-context").textContent = pfWorkspace ? "工作区 · " + pathName(pfWorkspace) : "全部工作区";
    $("#filter-context").title = pfWorkspace;

    var hint = document.getElementById("pf-hint");
    hint.textContent = d.ledger ? "台账：" + d.ledger + "（只记路径与交付，不存结论）" : "";

    var box = document.getElementById("projects");
    box.textContent = "";
    if (!(d.projects || []).length) {
      var filtered = !!(pfWorkspace || pfStage || $("#pf-q").value.trim());
      listState(filtered ? "没有匹配的项目" : "还没有项目",
        filtered ? "换个关键词，或清除状态与工作区筛选。" : "添加一个目标和工作区，开始记录安全实验。",
        filtered ? "清除筛选" : "添加项目", function () {
          if (!filtered) { go("#/new"); return; }
          pfWorkspace = pfStage = "";
          $("#pf-q").value = "";
          loadProjects();
        });
      return;
    }
    d.projects.forEach(function (p) { box.appendChild(projectCard(p)); });
  }

  function stageChip(id, label, count, icon) {
    var active = view === "projects" && pfStage === id;
    var c = el("button", "nav-item" + (active ? " active" : ""));
    c.type = "button";
    c.setAttribute("aria-pressed", String(active));
    var mark = el("span", "nav-icon", icon || "○");
    mark.setAttribute("aria-hidden", "true");
    c.appendChild(mark);
    c.appendChild(el("span", "nav-label", label));
    c.appendChild(el("span", "nav-count", count));
    c.addEventListener("click", function () {
      pfStage = id;
      if (view !== "projects") go("#/");
      else { loadProjects(); setSidebar(false); }
    });
    return c;
  }

  function pathName(path) {
    var parts = String(path || "").replace(/[\\/]+$/, "").split(/[\\/]/);
    return parts[parts.length - 1] || path;
  }

  function renderNavigation(d) {
    var tally = $("#pf-stages"), counts = {}, total = 0, inflight = 0;
    tally.textContent = "";
    (d.stages || []).forEach(function (s) {
      counts[s.id] = s.count || 0;
      total += s.count || 0;
      if (s.inflight) inflight += s.count || 0;
    });
    [["", "全部项目", total, "▦"], ["inflight", "进行中", inflight, "◷"],
      ["review", "待复核", counts.review || 0, "◉"],
      ["deliverable", "可交付", counts.deliverable || 0, "✓"],
      ["delivered", "已交付", counts.delivered || 0, "□"]].forEach(function (s) {
        tally.appendChild(stageChip(s[0], s[1], s[2], s[3]));
      });
    var extra = el("details", "nav-extra");
    extra.appendChild(el("summary", null, "其他阶段"));
    (d.stages || []).forEach(function (s) {
      if (["review", "deliverable", "delivered"].indexOf(s.id) >= 0 || (!s.count && pfStage !== s.id)) return;
      extra.appendChild(stageChip(s.id, STAGE_CN[s.id] || s.label, s.count || 0));
      if (pfStage === s.id) extra.open = true;
    });
    if (extra.children.length > 1) tally.appendChild(extra);
    var wsSel = $("#pf-ws"), box = $("#nav-workspaces");
    wsSel.textContent = box.textContent = "";
    [""].concat(d.workspaces || []).forEach(function (w) {
      var name = w ? pathName(w) : "全部工作区";
      if (w && (d.workspaces || []).filter(function (p) { return pathName(p) === name; }).length > 1) name = w;
      var option = el("option", null, name);
      option.value = w;
      wsSel.appendChild(option);
      var b = el("button", "nav-item" + (pfWorkspace === w ? " active" : ""));
      b.type = "button";
      b.title = w || "全部工作区";
      b.setAttribute("aria-pressed", String(pfWorkspace === w));
      var mark = el("span", "nav-icon", w ? "▱" : "⊞");
      mark.setAttribute("aria-hidden", "true");
      b.appendChild(mark);
      b.appendChild(el("span", "nav-label", name));
      b.addEventListener("click", function () {
        pfWorkspace = w;
        if (view !== "projects") go("#/");
        else { loadProjects(); setSidebar(false); }
      });
      box.appendChild(b);
    });
    wsSel.value = pfWorkspace;
  }

  function loadNavigation() {
    api("/api/projects").then(function (d) {
      if (view !== "projects") renderNavigation(d);
    }).catch(function () {
      var box = $("#pf-stages");
      if (!box.children.length) box.appendChild(stageChip("", "全部项目", "", "▦"));
    });
  }

  function listState(title, description, action, handler, error) {
    var box = $("#projects");
    box.textContent = "";
    var card = el("div", "list-state" + (error ? " error" : ""));
    card.setAttribute("role", error ? "alert" : "status");
    card.appendChild(el("h2", null, title));
    card.appendChild(el("p", null, description));
    var button = el("button", "btn" + (error ? "" : " primary"), action);
    button.type = "button";
    button.addEventListener("click", handler);
    card.appendChild(button);
    box.appendChild(card);
  }

  function setSidebar(open) {
    var toggle = $("#sidebar-toggle");
    if (open) sidebarReturn = document.activeElement;
    document.body.classList.toggle("sidebar-open", open);
    $("#sidebar-shade").hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    if (open) $("#sidebar-close").focus();
    else if (sidebarReturn) {
      if (sidebarReturn.isConnected && sidebarReturn.getClientRects().length) sidebarReturn.focus();
      else if (toggle.getClientRects().length) toggle.focus();
      sidebarReturn = null;
    }
  }

  function selectPanel(id) {
    document.querySelectorAll("[data-panel]").forEach(function (n) {
      var selected = n.getAttribute("data-panel") === id;
      n.classList.toggle("active", selected);
      if (selected) n.setAttribute("aria-current", "location");
      else n.removeAttribute("aria-current");
    });
  }

  function projectCard(p) {
    var card = el("a", "pcard" + (p.deliverable ? " ready" : "") + (p.exists ? "" : " gone"));
    card.href = "#/p/" + encodeURIComponent(p.alias);
    var top = el("div", "pcard-top");
    top.appendChild(el("span", "pname", p.name || p.alias));
    top.appendChild(el("span", "pill stage-" + p.stage, p.stage_label || p.stage));
    top.appendChild(el("span", "spacer"));
    top.appendChild(el("span", "mono mute pcard-alias", p.alias || ""));
    card.appendChild(top);
    var root = el("div", "pcard-meta mono mute truncate", p.root || "");
    root.title = p.root || "";
    card.appendChild(root);

    var counts = p.counts || {};
    var line = el("div", "pcard-counts");
    line.appendChild(el("span", null, "证据 " + (counts.evidence || 0)));
    line.appendChild(el("span", counts.confirmed ? "ok" : "mute", "已确认 " + (counts.confirmed || 0)));
    line.appendChild(el("span", counts.hypothesis ? "warn" : "mute",
      "待验证 " + (counts.hypothesis || 0)));
    line.appendChild(el("span", "mute", "已否定 " + (counts.refuted || 0)));
    if (counts.pending) line.appendChild(el("span", "warn", "待审批 " + counts.pending));
    if (counts.candidates !== null && counts.candidates !== undefined) {
      line.appendChild(el("span", "mute", "候选 " + counts.candidates));
    }
    card.appendChild(line);
    card.appendChild(el("div", "pcard-why", p.why || p.error || ""));
    var activity = el("time", "pcard-activity");
    var when = p.last_activity ? new Date(p.last_activity) : null;
    if (when && !isNaN(when.getTime())) {
      activity.dateTime = when.toISOString();
      activity.title = when.toLocaleString("zh-CN");
      activity.textContent = when.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
    } else activity.textContent = "暂无活动记录";
    card.appendChild(activity);
    return card;
  }

  // ---------- 详情 ----------
  function loadProject(alias) {
    return api("/api/projects/" + encodeURIComponent(alias)).then(function (d) {
      var p = d.project || {};
      if (view !== "project" || alias !== project) return;
      pDetail = d;
      $("#nav-project-name").textContent = p.name || p.alias || alias;
      document.getElementById("p-name").textContent = p.name || p.alias || alias;
      var pill = document.getElementById("p-stage");
      pill.textContent = d.stage_label || d.stage || "—";
      pill.className = "pill stage-" + (d.stage || "missing");
      var root = document.getElementById("p-root");
      root.textContent = p.root || "";
      root.title = p.root || "";
      document.getElementById("p-why").textContent = d.why || "";
      renderSteps(d.steps || []);
      renderActions(d.next || []);
      renderCrumbs(p);
      document.getElementById("eng").textContent = p.engagement_id || "—";
      var chips = document.getElementById("scope-chips");
      chips.textContent = "";
      (p.domains || []).forEach(function (dom) { chips.appendChild(el("span", "chip", dom)); });
      if (p.delivered) chips.appendChild(el("span", "chip", "已交付 " + (p.delivered_at || "")));
    }).catch(function (e) {
      if (view !== "project" || alias !== project) return;
      document.getElementById("p-why").textContent = "读项目失败：" + e.message;
    });
  }

  function renderCrumbs(p) {
    var c = document.getElementById("crumbs");
    c.textContent = "";
    var a = el("a", null, "项目");
    a.href = "#/";
    c.appendChild(a);
    c.appendChild(el("span", "sep", "›"));
    c.appendChild(el("span", null, p.name || p.alias || ""));
  }

  function renderSteps(steps) {
    var box = document.getElementById("p-steps");
    box.textContent = "";
    steps.forEach(function (s, i) {
      var li = el("li", "step " + s.state);
      li.appendChild(el("span", "dotstep", String(i + 1)));
      var body = el("div", "step-body");
      body.appendChild(el("div", "step-label", s.label));
      body.appendChild(el("div", "step-detail mute", s.detail || ""));
      li.appendChild(body);
      box.appendChild(li);
    });
  }

  function renderActions(next) {
    var box = document.getElementById("p-actions");
    box.textContent = "";
    (next || []).forEach(function (a) {
      var cls = a.kind === "deliver" ? "primary" : "ghost";
      box.appendChild(actBtn(a.label, cls, function () { return doAction(a.kind); }));
    });
  }

  function doAction(kind) {
    var alias = project;
    if (!alias) return Promise.resolve();
    if (kind === "deliver") return setDelivered(true, false);
    if (kind === "undeliver") return setDelivered(false, false);
    if (kind === "identity") { openIdentity(); return Promise.resolve(); }
    if (kind === "recon") { openRecon(); return Promise.resolve(); }
    if (kind === "review") {
      var f = document.getElementById("findings");
      if (f && f.scrollIntoView) f.scrollIntoView({ behavior: "smooth", block: "center" });
      return Promise.resolve();
    }
    if (kind === "round") {
      return startJob("/api/projects/" + encodeURIComponent(alias) + "/round",
        { max_rounds: 1, max_candidates: 5 });
    }
    if (kind === "report") {
      return startJob("/api/projects/" + encodeURIComponent(alias) + "/report", { html: true });
    }
    return Promise.resolve();
  }

  function setDelivered(delivered, force) {
    var alias = project;
    return post("/api/projects/" + encodeURIComponent(alias) + "/deliver",
      { delivered: !!delivered, force: !!force })
      .then(function (r) {
        toast(delivered ? "已记下交付" : "已撤回交付");
        return loadProject(alias).then(function () {
          if (!delivered) return refresh();
        });
      })
      .catch(function (e) {
        if (delivered && !force && e.data && e.data.error === "not_deliverable") {
          if (window.confirm("现在还不能交付：" + (e.data.why || e.message) +
            "\n\n还是要标成交付吗？")) {
            return setDelivered(true, true);
          }
          return;
        }
        toast("操作失败：" + e.message, "err");
      });
  }

  // ---------- 后台任务 ----------
  function startJob(url, body) {
    return post(url, body).then(function (r) {
      var job = r.job || {};
      toast("已开始：" + (job.label || job.kind) + "（后台跑，完成会提示）");
      showJob(job);
      trackJob(project);
    }).catch(function (e) {
      if (e.data && e.data.error === "job_running") {
        toast("这个项目已经在跑了：" + ((e.data.job || {}).label || ""), "warn");
      } else {
        toast("启动失败：" + e.message, "err");
      }
    });
  }

  function showJob(job) {
    var line = document.getElementById("p-job");
    if (!line) return;
    if (!job) { line.hidden = true; line.textContent = ""; return; }
    var prog = job.progress || [];
    line.hidden = false;
    line.className = "jobline " + (job.state || "");
    line.textContent = "后台：" + (job.label || job.kind) + " · " + (job.state || "") +
      (job.error ? " · " + job.error : "") +
      (prog.length ? " · " + prog[prog.length - 1] : "");
  }

  function trackJob(alias) {
    if (jobTimer) clearInterval(jobTimer);
    var tries = 0;
    jobTimer = setInterval(function () {
      tries += 1;
      if (view !== "project" || tries > 240) { clearInterval(jobTimer); jobTimer = null; return; }
      api("/api/jobs?project=" + encodeURIComponent(alias)).then(function (d) {
        var mine = (d.jobs || []).filter(function (j) { return j.alias === alias; })[0];
        if (!mine) return;
        showJob(mine);
        if (mine.state === "done" || mine.state === "failed") {
          clearInterval(jobTimer); jobTimer = null;
          toast(mine.state === "done" ? "后台跑完了：" + (mine.label || mine.kind)
            : "后台失败：" + (mine.error || "?"), mine.state === "done" ? "" : "err");
          loadProject(alias);
          if (view === "project") refresh();
        }
      }).catch(function () { /* 下一轮再试 */ });
    }, 2500);
  }

  // ---------- 新建项目 ----------
  function submitNew(ev) {
    ev.preventDefault();
    var body = {
      name: document.getElementById("new-name").value.trim(),
      url: document.getElementById("new-url").value.trim(),
      workspace: document.getElementById("new-ws").value.trim(),
      note: document.getElementById("new-note").value.trim()
    };
    var btn = document.getElementById("new-submit");
    btn.disabled = true;
    post("/api/projects", body).then(function (r) {
      var p = r.project || {};
      var imported = (r.created || {}).imported;
      toast((imported ? "这个工作区本来就在，已收进台账：" : "项目建好了：") +
        (p.name || p.alias || body.name));
      if (r.ledger_error) toast("但台账没写成：" + r.ledger_error, "warn");
      if (p.alias) {
        setProject(p.alias);
        go("#/p/" + encodeURIComponent(p.alias));
      } else {
        go("#/");
      }
    }).catch(function (e) {
      var has = e.data && e.data.alias;
      toast("创建失败：" + e.message + (has ? "（已有项目 " + e.data.alias + "）" : ""), "err");
      if (has) {
        setProject(e.data.alias);
        go("#/p/" + encodeURIComponent(e.data.alias));
      }
    }).then(function () { btn.disabled = false; });
  }

  // ---------- 导入登录态 / 侦察 ----------
  function openIdentity() {
    var dlg = document.getElementById("identity-dialog");
    document.getElementById("id-name").value = "A";
    document.getElementById("id-cookie").value = "";
    document.getElementById("id-headers").value = "";
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute("open", "");
  }

  function submitIdentity(ev) {
    ev.preventDefault();
    var body = {
      identity: document.getElementById("id-name").value.trim(),
      cookie: document.getElementById("id-cookie").value.trim(),
      headers: {}
    };
    document.getElementById("id-headers").value.split(/\r?\n/).forEach(function (line) {
      var at = line.indexOf(":");
      if (at > 0) body.headers[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    });
    var btn = ev.target.querySelector("button.primary");
    if (btn) btn.disabled = true;
    post("/api/projects/" + encodeURIComponent(project) + "/identity", body)
      .then(function (r) {
        toast("已存身份 " + r.identity);
        document.getElementById("identity-dialog").close();
        return loadProject(project);
      })
      .catch(function (e) { toast("保存失败：" + e.message, "err"); })
      .then(function () { if (btn) btn.disabled = false; });
  }

  function openRecon() {
    var f = (pDetail && pDetail.facts) || {};
    var host = ((f.domains || [])[0]) || "";
    var port = (f.allowed_ports || []).filter(function (p) { return p !== 80 && p !== 443; })[0];
    var scheme = (f.allowed_ports || []).indexOf(443) >= 0 && !port ? "https" : "http";
    document.getElementById("recon-seed").value = host
      ? scheme + "://" + host + (port ? ":" + port : "") + "/" : "";
    document.getElementById("recon-identity").value =
      ((f.identities || [])[0]) || "";
    document.getElementById("recon-pages").value = "25";
    document.getElementById("recon-depth").value = "2";
    var dlg = document.getElementById("recon-dialog");
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute("open", "");
  }

  function submitRecon(ev) {
    ev.preventDefault();
    return startJob("/api/projects/" + encodeURIComponent(project) + "/recon", {
      seed: document.getElementById("recon-seed").value.trim(),
      identity: document.getElementById("recon-identity").value.trim(),
      max_pages: parseInt(document.getElementById("recon-pages").value, 10) || 25,
      max_depth: parseInt(document.getElementById("recon-depth").value, 10) || 0
    }).then(function () {
      var dlg = document.getElementById("recon-dialog");
      if (dlg.close) dlg.close();
    });
  }

  // ---------- 刷新 ----------
  function refresh() {
    if (view !== "project" || !project) return Promise.resolve();
    var alias = project;
    return api("/api/state").then(function (s) {
      if (view !== "project" || project !== alias) return;
      state = s;
      renderHeader(s);
      renderFindings(s);
      renderAssets(s);
      renderApprovals(s);
      renderEvidence(s);
      if (selA || selB) renderDiff();
      setConn(true);
    }).catch(function (e) {
      if (view !== "project" || project !== alias) return;
      setConn(false, e.message);
    });
  }

  function setConn(ok, msg) {
    var dot = $("#dot");
    dot.className = "dot " + (ok ? "on" : "off");
    $("#conn-text").textContent = ok ? "已连接" : ("断开：" + (msg || "?"))
      ;
  }

  // ---------- SSE ----------
  var es = null;
  function connect() {
    if (!window.EventSource) { setConn(false, "浏览器不支持 SSE"); return; }
    if (es) { try { es.close(); } catch (e) { /* ignore */ } }
    var url = "/api/stream" + (project ? "?project=" + encodeURIComponent(project) : "");
    es = new EventSource(url);
    es.onopen = function () { setConn(true); };
    es.onerror = function () { setConn(false, "SSE 重连中"); };
    es.onmessage = function (m) {
      var ev = null;
      try { ev = JSON.parse(m.data); } catch (e) { return; }
      if (!ev || !ev.type) return;
      if (ev.type === "approval_required") {
        toast("L2 动作待审批：" + ev.host + " " + (ev.param_path || "") + " (" + ev.level + ")", "warn");
      } else if (ev.type === "approval_decided") {
        toast("审批已处理：" + String(ev.fp || "").slice(0, 10));
      } else if (ev.type === "run_finished") {
        toast("模板跑完：" + (ev.status || "?") + " · " + (ev.template_id || ""));
      } else if (ev.type === "run_failed") {
        toast("模板失败：" + (ev.reason || "?"), "err");
      } else if (ev.type === "finding_overridden") {
        toast("finding 已改：" + String(ev.id || "").slice(0, 8) + " → " + ev.status);
      } else if (ev.type === "job_started") {
        toast("后台开始：" + ((ev.job || {}).label || ""));
      } else if (ev.type === "job_finished") {
        showJob(ev.job);
      }
      if (view === "project") refresh();
    };
  }

  // ---------- 事件绑定 ----------
  function bind() {
    $(".workspace-brand").addEventListener("click", function (e) {
      e.preventDefault();
      pfStage = pfWorkspace = "";
      $("#pf-q").value = "";
      go("#/");
    });
    $(".skip-link").addEventListener("click", function (e) {
      e.preventDefault();
      $("#main-content").focus();
    });
    document.querySelectorAll(".field").forEach(function (field) {
      var label = field.querySelector("label"), input = field.querySelector("input, select, textarea");
      if (label && input && input.id) label.htmlFor = input.id;
    });
    $("#sidebar-toggle").addEventListener("click", function () { setSidebar(true); });
    $("#sidebar-close").addEventListener("click", function () { setSidebar(false); });
    $("#sidebar-shade").addEventListener("click", function () { setSidebar(false); });
    window.addEventListener("resize", function () {
      if (window.innerWidth > 900) setSidebar(false);
    });
    document.querySelectorAll("[data-panel]").forEach(function (n) {
      n.addEventListener("click", function () {
        var id = n.getAttribute("data-panel"), target = document.getElementById(id);
        selectPanel(id);
        setSidebar(false);
        if (target) { target.scrollIntoView({ block: "start", behavior: "auto" }); target.focus({ preventScroll: true }); }
      });
    });
    $("#drawer-close").addEventListener("click", function () { $("#drawer").classList.remove("open"); });
    $("#btn-clear-diff").addEventListener("click", function () {
      selA = selB = null;
      renderEvidence(state);
      renderDiff();
    });
    $("#ev-filter").addEventListener("input", function (e) {
      evFilter = e.target.value.trim();
      renderEvidence(state);
    });
    $("#btn-run").addEventListener("click", openRunDialog);
    $("#run-form").addEventListener("submit", submitRun);
    $("#btn-critic").addEventListener("click", function () {
      toast("正在复核…");
      post("/api/critic", {}).then(function (r) {
        var c = r.counts || {};
        toast("复核完成：保留 " + (c.kept || 0) + " / 否决 " + (c.vetoed || 0) + " / 提醒 " + (c.warned || 0));
        return refresh();
      }).catch(function (e) { toast("复核失败：" + e.message, "err"); });
    });
    $("#btn-plan").addEventListener("click", function () {
      toast("Planner 正在提候选…");
      post("/api/plan", {}).then(function (r) {
        var notes = $("#plan-notes");
        notes.textContent = "";
        var head = el("div", "mute", "计划来源：" + (r.source || "?") +
          "，候选 " + ((r.candidates || []).length) + " 条" + (r.degraded ? "（模型不可用，已降级为规则）" : ""));
        notes.appendChild(head);
        (r.candidates || []).forEach(function (c) {
          var tail = "  优先级 " + (c.priority || 0).toFixed(2) +
            (c.source === "graph" ? "  ≈" : "");
          var line = el("div", "cand mono", "· " + c.template_id + "  " + c.url + tail);
          line.title = (c.rationale || "") + "（点一下，填进「跑模板」）";
          line.addEventListener("click", function () { openRunDialog(c); });
          notes.appendChild(line);
        });
        (r.rejected || []).slice(0, 5).forEach(function (x) {
          notes.appendChild(el("div", "mute", "× " + (x.reason || "") + " " + (x.url || "")));
        });
        return refresh();
      }).catch(function (e) { toast("提候选失败：" + e.message, "err"); });
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { $("#drawer").classList.remove("open"); setSidebar(false); }
      if (e.key === "Tab" && document.body.classList.contains("sidebar-open")) {
        var nodes = Array.prototype.filter.call($("#sidebar").querySelectorAll("a[href], button, summary"), function (n) { return n.getClientRects().length; });
        var first = nodes[0], last = nodes[nodes.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });

    // ---- 项目壳 ----
    window.addEventListener("hashchange", function () {
      route();
      connect();
    });
    $("#btn-new").addEventListener("click", function () { go("#/new"); });
    $("#new-form").addEventListener("submit", submitNew);
    $("#identity-form").addEventListener("submit", submitIdentity);
    $("#recon-form").addEventListener("submit", submitRecon);
    $("#p-refresh").addEventListener("click", function () {
      if (project) { loadProject(project); refresh(); }
    });
    var pfq = $("#pf-q");
    var timer = null;
    pfq.addEventListener("input", function () {
      if (timer) clearTimeout(timer);
      timer = setTimeout(loadProjects, 200);       // 打字时别每敲一下就重排
    });
    $("#pf-ws").addEventListener("change", function (e) {
      pfWorkspace = e.target.value || "";
      loadProjects();
    });
  }

  bind();
  route();
  connect();
  setInterval(function () {
    // SSE 只用来提醒，真正的状态仍以拉取为准（断线时也不会看到过期数据）
    if (document.visibilityState === "visible" && view === "project") refresh();
  }, 5000);
})();
