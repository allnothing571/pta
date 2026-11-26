"""P1 执行闭环：vhx 模板 → 动作序列 → http_probe → oracle → finding。

设计约束：
- Executor 不发明动作，只把模板里的 sequence 展开成 ProbeRequest
- 判定只发生在 oracle 里；engine 只负责"哪两条证据配对"
- 模板 budget.max_requests 是硬上限，超了就停并记录 stop_reason
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlsplit

from . import graph as gref
from . import jwtlab, payloads
from .browser import NavRequest
from .channels import BLOCK_STATUS as CHANNEL_BLOCK_STATUS
from .channels import Channel, ChannelProbe, ChannelReport
from .errors import VhxInvalid
from .models import CanonicalRequest, Evidence, sha256_hex, verdict_status
from .oracles import ORACLE_REGISTRY, Observation, load_observations
from .probe import ProbeRequest, ProbeTool, compute_evidence_id
from .store import Store
from .vhx import Template

SUPPORTED_ACTIONS = frozenset({"http_request", "swap_identity", "mutate_param", "timing_sample",
                               "diff_response", "replay", "oob_arm", "oob_check",
                               "browser_nav", "concurrent_burst", "batch_sweep"})
UNSUPPORTED_REASON = {"decode_token": "P1 无 JWT 解码器"}


@dataclass
class Target:
    """模板落到具体目标上的参数。"""
    url: str
    param_path: Optional[str] = None
    identity_baseline: str = "none"
    identity_probe: str = "none"
    identity_control: Optional[str] = None
    control_url: Optional[str] = None
    method: str = "GET"
    body_json: Optional[Dict[str, Any]] = None
    headers_extra: Tuple[Tuple[str, str], ...] = ()
    sample: int = 1
    oob_wait_s: float = 3.0
    id_plus_one: Optional[str] = None
    # 起始通道：plain（默认）/ browser / curl。被拦时引擎会自己换档，
    # 这里只决定"第一发用哪一档"（目标明确只认浏览器时可以直接从 browser 起）。
    channel: Optional[str] = None
    # 写后回读的目标：上传类模板的回读地址由"文件落到哪"决定，模板给不了，
    # 只能由操作者（或靶场）在目标里指定完整 URL。
    verify_url: Optional[str] = None


@dataclass
class Finding:
    id: str
    engagement_id: str
    template_id: str
    title: str
    status: str
    confidence: float
    evidence_ids: List[str]
    verdict: Dict[str, Any]
    stop_reason: str = ""
    requests_used: int = 0

    def to_json(self) -> Dict[str, Any]:
        return {
            "id": self.id, "template_id": self.template_id, "title": self.title,
            "status": self.status, "confidence": round(self.confidence, 4),
            "evidence_ids": self.evidence_ids, "verdict": self.verdict,
            "stop_reason": self.stop_reason, "requests_used": self.requests_used,
        }


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def finding_id(template_id: str, evidence_ids: Sequence[str]) -> str:
    raw = template_id + "|" + "|".join(sorted(evidence_ids))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class Executor:
    def __init__(self, probe: ProbeTool, store: Store, scope_engagement: str,
                 browser: Optional[Any] = None, channels: Optional[ChannelProbe] = None):
        self.probe = probe
        self.store = store
        self.engagement_id = scope_engagement
        self.browser = browser          # BrowserTool；模板要 browser_nav 时必须给
        # 通道消歧：被拦时换客户端身份重发，判断"这次被拒"是不是我们自己太显眼
        self.channels = channels or ChannelProbe(probe)
        self._channel: Optional[Channel] = None
        self._channel_report: Optional[ChannelReport] = None
        self._net_error: str = ""
        self._deny_reason: str = ""
        # 单次请求超时：模板可以收紧（SSRF 打不可达的内网地址时，10s 是白等）
        self.timeout_s: Optional[float] = None

    # ---------- 主入口 ----------
    def run(self, template: Template, target: Target, run_id: Optional[str] = None) -> Finding:
        raw = template.raw
        self._channel = None
        self._channel_report = None
        self._net_error = ""
        self._deny_reason = ""
        sequence = raw["probe"].get("sequence") or [raw["probe"]["action"]]
        for act in sequence:
            if act in UNSUPPORTED_REASON:
                raise VhxInvalid("模板 %s 需要 %s：%s" % (template.id, act, UNSUPPORTED_REASON[act]))
            if act not in SUPPORTED_ACTIONS:
                raise VhxInvalid("模板 %s 含未知动作 %s" % (template.id, act))

        cfg = raw.get("probe") or {}
        try:
            self.timeout_s = float(cfg.get("timeout_s") or 0) or None
        except (TypeError, ValueError):
            self.timeout_s = None
        run_id = run_id or hashlib.sha256(
            ("%s|%s|%s" % (template.id, target.url, _now())).encode()).hexdigest()[:8]
        label = "run/%s/%s" % (template.id, run_id)
        budget = int(raw["budget"]["max_requests"])
        used = 0
        stop = ""

        hints = [(h.get("payload_class"), h.get("payload_variant"))
                 for h in raw.get("mutator_hints", []) if h.get("payload_class")]
        if not hints:
            hints = [(None, None)]
        if (raw.get("probe") or {}).get("role_hints"):
            hints = []  # 注入次数改由 role_hints 决定，不再多打一发无载荷请求

        # id_shift 需要目标侧可推导的整数；推不出来就别发一条注定被拒的请求
        id_plus_one = target.id_plus_one or self._derive_id_plus_one(target)
        skipped: List[str] = []
        if id_plus_one is None and any(pc == "id_shift" for pc, _ in hints):
            hints = [(pc, pv) for pc, pv in hints if pc != "id_shift"] or [(None, None)]
            skipped.append("id_shift:目标 URL 无整数参数")

        # jwt_forged 需要当前身份真的有 token；没有就跳过（不发明凭据）
        if any(pc == "jwt_forged" for pc, _ in hints):
            tok = self.probe.vault.get("cred/%s/authorization" % target.identity_baseline) \
                if target.identity_baseline not in ("none", "", None) else None
            if not tok or not jwtlab.is_jwt(tok):
                hints = [(pc, pv) for pc, pv in hints if pc != "jwt_forged"] or [(None, None)]
                skipped.append("jwt_forged:该身份没有可用 JWT 凭据")

        roles: Dict[str, str] = {}
        baseline_id: Optional[str] = None
        probe_ids: List[str] = []
        del roles  # 角色映射只在单次判定内构造

        # 时间判定要求两组各采样若干次：baseline 与 probe 必须用同一个采样数，
        # 否则"注入组慢"可能只是采样次数不同带来的偏差。
        # 多要一次：时间判定要丢掉带冷启动开销的第一次采样（见 timing_distribution_shift）
        # 采样数：模板可以显式要（校准器会给出建议值），时间类至少要 6 次
        # ——丢 1 个冷启动后仍要有 5 个可比样本
        want = 0
        if isinstance(raw.get("probe"), dict):
            try:
                want = int((raw.get("probe") or {}).get("samples") or 0)
            except (TypeError, ValueError):
                want = 0
        sample = max(target.sample, want, 6) if "timing_sample" in sequence else \
            max(target.sample, want)

        # 起始客户端身份要在第一发之前定下来：否则"基线用某档、载荷换档"
        # 会变成自相矛盾的配对（基线 403、载荷 200，看起来像越权其实是换了 UA）。
        if target.channel:
            self._channel = self._channel_by_name(target.channel)

        # 1) baseline：模板里有 http_request/swap_identity 且给了 baseline 身份
        # 有些模板（SSRF 内网指纹）没有身份概念，但同样需要"不带载荷的同一请求"做对照，
        # 这类模板在 probe.baseline.required 里显式声明。
        baseline_cfg = (raw.get("probe") or {}).get("baseline")
        baseline_required = bool(isinstance(baseline_cfg, dict) and baseline_cfg.get("required"))
        needs_baseline = (target.identity_baseline not in ("none", "", None) or baseline_required) and (
            "http_request" in sequence or "swap_identity" in sequence or "diff_response" in sequence)
        # 写操作模板的 baseline 必须是"属主读一次"，而不是"属主也写一次"：
        # 探测方法由模板 probe.baseline.method 指定（默认沿用 target.method）
        base_method = (raw.get("probe") or {}).get("baseline", {}).get("method") \
            if isinstance((raw.get("probe") or {}).get("baseline"), dict) else None
        if needs_baseline and used < budget:
            bs = self._strip_for(raw, "baseline")
            r = self._send(target, label, target.identity_baseline, None, None,
                           sample=sample, method=base_method,
                           strip_headers=bs["headers"], strip_params=bs["params"])
            used += 1
            if r.status == "ok" and r.evidence_id:
                baseline_id = r.evidence_id
            elif r.status in ("denied", "pending_approval", "blocked"):
                stop = "baseline:%s" % r.status

        # 1a2) 通道消歧：基线自己就被拦了（403/429/503…），先分清是"应用层拒绝"
        #      还是"拦截层把我们当爬虫"。分不清就会把"有洞但被 WAF 挡"记成 refuted，
        #      那是最难自查的一种漏报（报告上写着"已否定"）。

        start_channel = self._channel_by_name(target.channel)
        if start_channel is not None:
            self._channel = start_channel
        if baseline_id and not stop and self._status(baseline_id) in CHANNEL_BLOCK_STATUS:
            # 可用预算要取两个数的较小者：模板这次的剩余额度，和全局账本的真实余量。
            # 只按模板算，会在"前面的候选已经花掉预算"时假装还有钱做消歧，
            # 结果三档各挨一次 BudgetExceeded，最后把原因误报成 unreachable。
            snap = self.probe.budget.snapshot()
            budget_left = min(budget - used, snap["max"] - snap["used"])
            report = self._probe_channels(
                target, identity=target.identity_baseline,
                method=base_method or target.method, budget_left=budget_left)
            if report is None:
                # 预算连"换两档再看一眼"都不够：不许把 403 当"没洞"，
                # 标成未验证（0.5），让操作者放宽预算或带浏览器会话重跑。
                stop = "channel_unverified:budget"
            else:
                used += report.requests
                self._channel_report = report
                picked = report.best
                if report.verdict == "waf" and picked:
                    self._channel = self._channel_by_name(picked)
                    r2 = self._send(target, label, target.identity_baseline, None, None,
                                    sample=sample, method=base_method)
                    used += 1
                    if r2.status == "ok" and r2.evidence_id:
                        baseline_id = r2.evidence_id

                if self._channel is None and report.verdict in ("waf", "unreachable"):
                    # 只有"拦截层在挑客户端"和"根本连不上"才叫分不清。
                    # app_denied 是应用自己拒绝（三档一致、无拦截特征），
                    # 403 在那种语境里就是证据，交回 oracle 判否。
                    stop = "channel_blocked:%s" % report.verdict

        # 1a3) decoy：用同身份读一个不可能存在的对象，做"响应是否与对象 id 有关"的负对照。
        #      少了这一发，"两个身份读到同一份内容"既可能是越权，也可能是公开资源
        #      或服务端根本没看 id——两者相似度都是 1.0，光看相似度分不开。
        decoy_id: Optional[str] = None
        if (raw.get("probe") or {}).get("decoy") and not stop and used < budget:
            durl = gref.decoy_url(target.url)
            if durl:
                rd = self._send(target, label, target.identity_baseline or "none", None, None,
                                sample=1, method=base_method, url=durl)
                used += 1
                if rd.status == "ok" and rd.evidence_id:
                    decoy_id = rd.evidence_id

        # 1b) control：同一主机上一个已知需要授权的接口，取一次真实的 401/403 当拒绝模板
        #     也可以配 identity="none" 去取"匿名访问同一个接口"的结果——CSRF 要用它
        #     把"只校验会话"和"接口本来就公开"分开，后者不是 CSRF。
        control_id: Optional[str] = None
        control_cfg = raw.get("probe", {}).get("control") or {}
        if control_cfg and target.control_url and not stop and used < budget:
            c_identity = str(control_cfg.get("identity") or target.identity_probe)
            rc = self._send(target, label, c_identity, None, None,
                            url=target.control_url)
            used += 1
            if rc.status == "ok" and rc.evidence_id:
                control_id = rc.evidence_id
            elif rc.status in ("denied", "pending_approval", "blocked"):
                stop = "control:%s" % rc.status

        # 1c) 多角色注入：一个 baseline 之外，按 role_hints 分别注入两次
        #     （布尔盲注要 1=1 与 1=2 两份响应，oracle 才能比出"差异只来自布尔条件"）
        #     这类模板不再走下面的"逐个载荷"循环：注入次数由 role_hints 决定。
        role_cfg = (raw.get("probe") or {}).get("role_hints") or []
        best: Optional[Tuple[float, List[str], Dict[str, Any], str]] = None
        if role_cfg and not stop:
            role_ids: Dict[str, str] = {}
            for h in role_cfg:
                if used >= budget:
                    stop = stop or "budget_exhausted"
                    break
                rh = self._send(target, label, target.identity_probe,
                                h.get("param_path") or target.param_path,
                                h.get("payload_class"),
                                payload_variant=h.get("payload_variant"),
                                level=raw.get("side_effect_level"), sample=sample)
                used += 1
                if rh.status == "pending_approval":
                    stop = "pending_approval:%s" % rh.approval_fp
                    break
                if rh.status in ("denied", "blocked"):
                    stop = "%s:%s" % (rh.status, rh.reason)
                    break
                if rh.status == "error":
                    continue
                if rh.status == "ok" and rh.evidence_id:
                    role_ids[h["role"]] = rh.evidence_id
                    probe_ids.append(rh.evidence_id)
            if role_ids and not stop:
                current_roles: Dict[str, str] = {}
                if baseline_id:
                    current_roles[baseline_id] = "baseline"
                if control_id:
                    current_roles[control_id] = "control"
                if decoy_id:
                    current_roles[decoy_id] = "decoy"
                for role, eid in role_ids.items():
                    current_roles[eid] = role
                v = self._judge(raw, label, current_roles, [])
                if v is not None:
                    ids = [i for i in (baseline_id, control_id, decoy_id) if i] + \
                          [role_ids[k] for k in role_ids]
                    verdict_json = self._verdict_json(v)
                    if v.passed:
                        return self._finalize(raw, ids, v.confidence, verdict_json, stop, used,
                                              current_roles)
                    best = (v.confidence, ids, verdict_json, "")

        # 2) 逐个载荷尝试，直到 oracle 通过或预算/停条件触发
        consecutive_blocks = 0
        for pc, pv in hints:
            if stop or used >= budget:
                if used >= budget and not stop:
                    stop = "budget_exhausted"
                break
            probe_id = None
            token = None
            sweep_ids_all: List[str] = []
            if "browser_nav" in sequence:
                # 浏览器只做"脚本是否执行"的判定：拿 DOM 快照当证据
                if self.browser is None:
                    raise VhxInvalid("模板 %s 需要浏览器，但工作区未启用 browser_nav" % template.id)
                nav = self.browser.navigate(NavRequest(
                    url=target.url, label=label, param_path=target.param_path,
                    payload_class=pc, payload_variant=pv, identity=target.identity_probe,
                ))
                if nav.status == "ok" and nav.evidence_id:
                    probe_id = nav.evidence_id
                    probe_ids.append(probe_id)
                elif nav.status in ("denied", "blocked"):
                    stop = "browser:%s" % nav.reason
                    break
                else:
                    consecutive_blocks += 1
                    if consecutive_blocks >= 3:
                        stop = "browser_errors"
                        break
                    continue
            elif "oob_arm" in sequence:
                if getattr(self.probe, "oob", None) is None:
                    raise VhxInvalid("模板 %s 需要 OOB 收集器，但工作区未启用" % template.id)
                token = self.probe.oob.arm(label, note=pc or "")
            r = None
            burst_statuses: Tuple[int, ...] = ()
            burst_labels: Tuple[str, ...] = ()
            counted = False
            ps = self._strip_for(raw, "probe")
            if "browser_nav" not in sequence:
                if "batch_sweep" in sequence:
                    # 批量读：同一身份把相邻对象挨个读一遍。判的不是"某一个能不能读"
                    # ——那个可能本来就是公开对象，也可能正好是我的；判的是"能读多少个"。
                    bcfg = (raw.get("probe") or {}).get("batch") or {}
                    count = int(bcfg.get("count") or 20)
                    step = int(bcfg.get("step") or 1)
                    # 留一发：后面的 decoy 与收尾还要花预算，不能一次扫光
                    room = max(0, budget - used - 1)
                    urls = gref.sweep_urls(target.url, min(count, room), step)
                    if not urls:
                        stop = ("sweep:no_object_slot"
                                if not gref.sweep_urls(target.url, 1, step)
                                else "sweep:no_budget")
                        break
                    sweep_ids, sstop = self._send_sweep(
                        target, label, urls, pc, pv,
                        raw.get("side_effect_level"), sample)
                    used += len(sweep_ids)
                    counted = True
                    if sstop:
                        stop = sstop
                    if not sweep_ids:
                        consecutive_blocks += 1
                        if consecutive_blocks >= 3:
                            stop = "sweep_errors"
                        continue
                    probe_id = sweep_ids[0]
                    probe_ids.extend(sweep_ids)
                    sweep_ids_all = list(sweep_ids)
                    # 每发一条独立证据（label 带 #i）。oracle 要按这些条目算比例，
                    # 而 _judge 按 label 只取得到一条，所以全部 label 都得交过去。
                    burst_labels = tuple("%s#%d" % (label, i)
                                         for i in range(len(sweep_ids)))
                elif "concurrent_burst" in sequence:
                    # 竞态：同一请求并发 N 发。nonce 必须固定——随机 nonce 会让
                    # N 发变成"N 个不同操作"，服务端当然都接受，结论就是假的。
                    burst_n = int((raw.get("probe") or {}).get("burst") or 5)
                    statuses, ids, bstop = self._send_burst(
                        target, label, target.identity_probe, target.param_path, pc,
                        burst_n, payload_variant=pv, level=raw.get("side_effect_level"),
                        nonce_value=self._race_nonce(raw.get("id") or "", target.method,
                                                     target.url, target.param_path))
                    used += len(statuses) or burst_n
                    counted = True
                    burst_statuses = tuple(statuses)
                    # 每发一条独立证据（label 带 #i）。oracle 只看其中一条，
                    # 所以这里要把全部 label 交给 _judge，否则它一条也取不到。
                    burst_labels = tuple("%s#%d" % (label, i)
                                         for i in range(max(2, burst_n)))
                    if bstop:
                        stop = bstop
                    elif not ids:
                        consecutive_blocks += 1
                        if consecutive_blocks >= 3:
                            stop = "burst_errors"
                        continue
                    else:
                        probe_id = ids[0]
                        probe_ids.extend(ids)
                else:
                    if "oob_arm" in sequence:
                        if getattr(self.probe, "oob", None) is None:
                            raise VhxInvalid("模板 %s 需要 OOB 收集器，但工作区未启用" % template.id)
                        token = self.probe.oob.arm(label, note=pc or "")
                    if pc is None and not target.param_path:
                        # 无参模板（如路径型泄露）：URL 本身就是探测目标
                        r = self._send(target, label, target.identity_probe, None, pc, token,
                                       payload_variant=pv, level=raw.get("side_effect_level"),
                                       sample=sample,
                                       strip_headers=ps["headers"], strip_params=ps["params"])
                    else:
                        r = self._send(target, label, target.identity_probe, target.param_path, pc,
                                       token, payload_variant=pv, level=raw.get("side_effect_level"),
                                       sample=sample,
                                       strip_headers=ps["headers"], strip_params=ps["params"])
            if not counted:
                used += 1

            if r is not None:
                if r.status == "pending_approval":
                    stop = "pending_approval:%s" % r.approval_fp
                    break
                if r.status in ("denied", "blocked"):
                    stop = "%s:%s" % (r.status, r.reason)
                    break
                if r.status == "error":
                    consecutive_blocks += 1
                    if consecutive_blocks >= 3:
                        stop = "transport_errors"
                        break
                    continue
                if r.status == "ok" and r.evidence_id:
                    probe_id = r.evidence_id
                    probe_ids.append(probe_id)
                    if r.extract and r.extract.status in CHANNEL_BLOCK_STATUS \
                            and not (ps["headers"] or ps["params"]):
                        # 这条 403 是我们自己"摘掉令牌"造成的，不是"我们被拦"：
                        # 在 CSRF 语义里它就是结论本身（防护在起作用），
                        # 拿去消歧只会把"有防护"洗成"被 WAF 挡住、没结论"。
                        # 载荷被拦：基线是通的，说明拦的是"这条载荷"而不是"我们"。
                        # 先换档重发一次——若换档就通，洞是真的，WAF 只是盖住了它。
                        if self._channel is None:
                            got, why, cost = self._retry_over_channel(
                                target, label, target.identity_probe, target.param_path,
                                pc, pv, raw.get("side_effect_level"),
                                target.method, budget - used, sample)
                            used += cost
                            if got:
                                probe_id = got
                                probe_ids.append(got)

                            elif why:
                                stop = why
                                break
                        if not stop:
                            rep = self._channel_report
                            if rep is not None and rep.verdict == "app_denied":
                                # 三档一律 403、无拦截特征：应用自己拒绝。
                                # 这种 403 是证据（"没权限"正是无洞的样子），
                                # 不进"被拦"计数，交给 oracle 按原规则判。
                                continue
                            consecutive_blocks += 1
                            if consecutive_blocks >= 3:
                                stop = "channel_blocked:waf"
                                break
            elif probe_id is None and not stop:
                # 浏览器分支失败（无证据）时继续下一组载荷
                continue

            # 2b) 写后回读：写操作本身只证明"被接受了"，要证明"真的改到了对方对象"，
            #     必须用对象的属主身份再读一次（写-读两段证据，只给一段都不判）。
            verify_id: Optional[str] = None
            verify_cfg = (raw.get("probe") or {}).get("verify_after") or {}
            if verify_cfg and probe_id and not stop and used < budget:
                v_role = verify_cfg.get("identity", "baseline")
                v_identity = (target.identity_baseline if v_role == "baseline"
                              else target.identity_probe)
                rv = self._send(target, label, v_identity, None, None,
                                method=verify_cfg.get("method", "GET"),
                                url=self._verify_url(target, verify_cfg))
                used += 1
                if rv.status in ("pending_approval", "denied", "blocked"):
                    stop = "%s:%s" % (verify_cfg.get("label", "verify"), rv.status)
                elif rv.status == "ok" and rv.evidence_id:
                    verify_id = rv.evidence_id
                    probe_ids.append(verify_id)

            # 只把"本次 baseline + 本次 probe"标成角色，避免历史 probe 混进配对
            current_roles: Dict[str, str] = {}
            if baseline_id:
                current_roles[baseline_id] = "baseline"
            if control_id:
                current_roles[control_id] = "control"
            if decoy_id:
                current_roles[decoy_id] = "decoy"
            if sweep_ids_all:
                # 第一发标 probe（oracle 的"探针"锚点），其余标 sweep
                current_roles[sweep_ids_all[0]] = "probe"
                for eid in sweep_ids_all[1:]:
                    current_roles[eid] = "sweep"
            elif probe_id:
                current_roles[probe_id] = "probe"
            if verify_id:
                if verify_id == baseline_id:
                    # 回读与基线内容完全相同 → 证据被去重成同一条，让它兼任两个角色，
                    # oracle 会判"回读与基线一致"，而不是"缺少 verify"
                    current_roles[baseline_id] = "baseline+verify"
                else:
                    current_roles[verify_id] = "verify"

            extra_obs: List[Observation] = []
            if token is not None and "oob_check" in sequence:
                callbacks = self.probe.oob.wait(token, timeout=target.oob_wait_s)
                for cb in callbacks:
                    obs_cb = self._persist_callback(cb, label)
                    extra_obs.append(obs_cb)
                    current_roles[obs_cb.evidence_id] = "callback"
                if not callbacks:
                    stop = stop or "no_callback"

            verdict = self._judge(raw, label, current_roles, extra_obs,
                                  burst_statuses, burst_labels)
            if verdict is None:
                continue
            cb_ids = [o.evidence_id for o in extra_obs]
            if best is None or verdict.confidence > best[0]:
                ids = self._merge_ids([baseline_id, control_id, decoy_id, probe_id, verify_id]
                                      + list(probe_ids) + cb_ids)
                best = (verdict.confidence, ids, self._verdict_json(verdict), "")
            if verdict.passed:
                ids = self._merge_ids([baseline_id, control_id, decoy_id, probe_id, verify_id]
                                      + list(probe_ids) + cb_ids)
                return self._finalize(raw, ids, verdict.confidence,
                                      self._verdict_json(verdict),
                                      stop, used, current_roles)

        if best is None:
            conf = 0.0
            if self._net_error and not probe_ids:
                # 连不上 ≠ 没有洞。端口写错、站点没起、代理挂了都会走到这里；
                # 若按 0 分落成"已否定"，报告上就是一条假的"这类漏洞不存在"。
                conf = 0.50
                rationale = ("目标连不上（%s）：这次既没有证据说'有洞'，也没有证据说'没洞'；"
                             "先确认地址、端口、代理和站点是否在运行" % self._net_error)
            elif stop.startswith("pending_approval"):
                rationale = "等待人工审批（%s），本次没有发出注入请求" % stop.split(":", 1)[-1]
            elif stop.startswith(("baseline:denied", "control:denied")):
                conf = 0.50
                rationale = ("请求被范围判定拒绝（%s）：%s"
                             % (stop, self._deny_reason or "未给出原因"))
            elif stop.startswith("channel_blocked"):
                # 被拦 ≠ 没有洞。给 0.5 是为了在面板上停在"待验证"，
                # 而不是和"确定无洞"混在同一个 0 分里。
                conf = 0.50
                rep = self._channel_report
                detail = rep.verdict if rep is not None else ""
                rationale = ("被拦截层挡住（%s）：换客户端身份后仍然被拒，"
                             "这次既没有证据说'有洞'，也没有证据说'没洞'；"
                             "换出口 IP 或带真实浏览器会话再跑" % (detail or "unknown"))
            elif stop.startswith("channel_unverified"):
                # 预算不足，连"换一档再看一眼"都做不到：同样不许判否
                conf = 0.50
                rationale = ("预算不够做通道消歧（%s）：被拒的原因分不清是"
                             "应用层拒绝还是拦截层拦截，这次不判有洞也不判没洞"
                             % stop.split(":", 1)[-1])
            else:
                rationale = "无有效判定输入"
                if skipped:
                    rationale += "；跳过 %s" % ",".join(skipped)
            # 这条分支在 current_roles 建好之前就可能到达（预算耗尽/被拒/连不上），
            # 角色表还不存在：只把发出去的那几条挂上，不编角色。
            return self._finalize(raw, probe_ids, conf,
                                  {"metrics": {}, "rationale": rationale}, stop or "no_verdict", used)
        conf, ids, verdict_json, _ = best
        if skipped:
            verdict_json = dict(verdict_json)
            verdict_json["rationale"] = "%s；跳过 %s" % (
                verdict_json.get("rationale", ""), ",".join(skipped))
            verdict_json["skipped"] = list(skipped)
        return self._finalize(raw, ids, conf, verdict_json, stop, used, current_roles)

    # ---------- 内部 ----------
    def _send(self, target: Target, label: str, identity: str,
              param_path: Optional[str], payload_class: Optional[str],
              oob_token: Optional[str] = None, payload_variant: Optional[str] = None,
              url: Optional[str] = None, level: Optional[str] = None,
              sample: Optional[int] = None, method: Optional[str] = None,
              channel: Optional[Channel] = None, nonce_value: Optional[str] = None,
              strip_headers: Tuple[str, ...] = (),
              strip_params: Tuple[str, ...] = ()):
        # 通道是"粘性"的：一旦证明某档能过拦截层，本次判定的后续请求都用它，
        # 否则会出现"基线用浏览器档、载荷用原样档"这种自相矛盾的配对。
        ch = channel if channel is not None else self._channel
        extra = tuple(target.headers_extra) + (tuple(ch.headers) if ch is not None else ())
        result = self.probe.run(ProbeRequest(
            action_id="exec:%s" % label,
            url=url or target.url,
            method=method or target.method,
            identity=identity,
            label=label,
            param_path=param_path,
            payload_class=payload_class,
            payload_variant=payload_variant,
            sample=sample or target.sample,
            body_kind="json" if target.body_json else "none",
            body_json=target.body_json,
            headers_extra=extra,
            asset_node_id=None,
            oob_token=oob_token,
            id_plus_one=target.id_plus_one or self._derive_id_plus_one(target),
            level=level,
            timeout_s=self.timeout_s or 10.0,
            nonce_value=nonce_value,
            strip_headers=strip_headers,
            strip_params=strip_params,
        ))
        # 记下"为什么这一发没发出去/没成功"，供最终 rationale 使用：
        # 「连不上」和「被范围拒绝」都必须能在结论里读到，否则用户只能猜。
        if result.status == "error" and not self._net_error:
            self._net_error = result.reason or "未知连接错误"
        if result.status == "denied" and not self._deny_reason:
            self._deny_reason = result.reason or ""
        return result

    def _send_burst(self, target: Target, label: str, identity: str,
                    param_path: Optional[str], payload_class: Optional[str],
                    burst: int, payload_variant: Optional[str] = None,
                    level: Optional[str] = None, nonce_value: Optional[str] = None):
        """同一请求并发 N 发。返回 (statuses, evidence_ids, stop_reason)。

        每发用不同的 evidence label（`burst:<n>`），否则 compute_evidence_id
        会把它们算成同一条证据、互相覆盖——那等于只留了最后一发的状态。
        """
        ch = self._channel
        extra = tuple(target.headers_extra) + (tuple(ch.headers) if ch is not None else ())
        reqs = [ProbeRequest(
            action_id="exec:%s#%d" % (label, i),
            url=target.url,
            method=target.method,
            identity=identity,
            label="%s#%d" % (label, i),
            param_path=param_path,
            payload_class=payload_class,
            payload_variant=payload_variant,
            sample=1,
            body_kind="json" if target.body_json else "none",
            body_json=target.body_json,
            headers_extra=extra,
            asset_node_id=None,
            id_plus_one=target.id_plus_one or self._derive_id_plus_one(target),
            level=level,
            timeout_s=self.timeout_s or 10.0,
            nonce_value=nonce_value,
        ) for i in range(max(2, int(burst)))]
        results = self.probe.send_burst(reqs)
        statuses: List[int] = []
        ids: List[str] = []
        stop = ""
        for r in results:
            if r.status == "ok" and r.evidence_id and r.extract is not None:
                statuses.append(int(r.extract.status))
                ids.append(r.evidence_id)
            elif r.status in ("pending_approval", "denied", "blocked"):
                # 前缀必须原样保留（pending_approval / denied / blocked），
                # _finalize 靠它决定状态；加 "burst:" 前缀会让"等审批"变成"无判定"。
                stop = stop or ("%s:%s" % (r.status, r.reason))
                break
            else:
                statuses.append(0)
        return statuses, ids, stop

    def _send_sweep(self, target: Target, label: str, urls: List[str],
                    payload_class: Optional[str], payload_variant: Optional[str] = None,
                    level: Optional[str] = None, sample: int = 1):
        """按顺序把一串对象 URL 各读一次。返回 (evidence_ids, stop_reason)。

        顺序发、不并发：这是"一路读下去"，并发只会让目标的风控先动手，而且
        服务端返回 429 之后剩下的读数全是噪声，比例就没意义了。
        被拒/等审批立刻停：那是"这一路走不下去"，不是"这个对象读不到"。
        """
        ids: List[str] = []
        stop = ""
        for i, u in enumerate(urls):
            r = self._send(target, "%s#%d" % (label, i), target.identity_probe,
                           target.param_path, payload_class,
                           payload_variant=payload_variant, level=level,
                           sample=sample, method=target.method, url=u)
            if r.status == "ok" and r.evidence_id:
                ids.append(r.evidence_id)
            elif r.status in ("pending_approval", "denied", "blocked"):
                stop = "%s:%s" % (r.status, r.reason)
                break
        return ids, stop

    # ---------- 通道 ----------
    def _channel_by_name(self, name: Optional[str]) -> Optional[Channel]:
        if not name:
            return None
        for ch in self.channels.channels:
            if ch.name == name:
                return ch
        return None

    def _status(self, evidence_id: str) -> int:
        row = self.store.get_evidence_row(evidence_id)
        try:
            return int(row["status"]) if row is not None else 0
        except (TypeError, ValueError):
            return 0

    def _probe_channels(self, target: Target, identity: str, method: str,
                        budget_left: int, param_path: Optional[str] = None,
                        payload_class: Optional[str] = None,
                        payload_variant: Optional[str] = None,
                        level: Optional[str] = None) -> Optional[ChannelReport]:
        """通道探测要花 2~3 次请求；预算不够时宁可不判，也不越过模板上限。"""
        if int(budget_left or 0) < 2:
            return None
        return self.channels.run(
            target.url, identity=identity, method=method,
            param_path=param_path, payload_class=payload_class,
            payload_variant=payload_variant, level=level,
            sample=1, timeout_s=self.timeout_s,
            extra_headers=target.headers_extra,
            # id_shift 这类载荷离开 id_plus_one 就生成不出来，通道实验会全部
            # 变成 "denied:payload"，把"没试成"记成"连不上"。
            id_plus_one=target.id_plus_one or self._derive_id_plus_one(target),
        )

    def _retry_over_channel(self, target: Target, label: str, identity: str,
                            param_path: Optional[str], payload_class: Optional[str],
                            payload_variant: Optional[str], level: Optional[str],
                            method: str, budget_left: int, sample: int):
        """载荷被拦时，带着这条载荷换档重发。返回 (证据 id, 停止原因, 花掉的请求数)。"""
        report = self._probe_channels(
            target, identity=identity, method=method, budget_left=budget_left,
            param_path=param_path, payload_class=payload_class,
            payload_variant=payload_variant, level=level)
        if report is None:
            return None, "channel_unverified:budget", 0
        self._channel_report = report
        cost = report.requests
        picked = report.best
        if report.verdict == "app_denied":
            # 三档一律 403、且没有任何拦截特征 → 是应用自己拒绝，不是"分不清"。
            # 403 在这种语境下本身就是证据（"没权限"正是无洞的样子），
            # 交回原来那条路（oracle 判 refuted），不要升成"未知"。
            return None, "", cost
        if report.verdict != "waf" or not picked:
            return None, "channel_blocked:%s" % report.verdict, cost
        self._channel = self._channel_by_name(picked)
        r = self._send(target, label, identity, param_path, payload_class,
                       payload_variant=payload_variant, level=level,
                       sample=sample, method=method)
        cost += 1
        if r.status == "ok" and r.evidence_id:
            return r.evidence_id, "", cost
        if r.status in ("denied", "blocked", "pending_approval"):
            return None, "channel_retry:%s" % r.status, cost
        return None, "", cost

    @staticmethod
    def _race_nonce(template_id: str, method: str, url: str, param_path: Optional[str]) -> str:
        """竞态用的固定标记：同一候选永远算出同一个值，重跑也能对上。

        故意不掺 run_id —— run_id 每次运行都不同，掺进去就等于"每次换一个标记"，
        服务端看到的是 N 个不同操作，重跑也无法复现上一次的请求体。
        """
        key = "%s|%s|%s|%s" % (template_id, method, url, param_path or "")
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]

    @staticmethod
    def _verify_url(target: Target, cfg: Dict[str, Any]) -> Optional[str]:
        """回读地址的优先级：Target.verify_url > 模板 url > 目标 origin + url_suffix。
        上传类模板只能给出"相对哪个路径回读"，落到哪个 origin 只有目标知道。"""
        if target.verify_url:
            return target.verify_url
        url = cfg.get("url")
        if url:
            return url
        suffix = cfg.get("url_suffix")
        if not suffix:
            return None
        parts = urlsplit(target.url)
        origin = "%s://%s" % (parts.scheme, parts.netloc)
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return origin + suffix

    @staticmethod
    def _derive_id_plus_one(target: Target) -> Optional[str]:
        """从 query 参数或路径尾部整数推导 +1，供 id_shift 用。"""
        parts = urlsplit(target.url)
        param = target.param_path or ""
        if param.startswith("query:"):
            name = param.split(":", 1)[1]
            vals = parse_qs(parts.query, keep_blank_values=True).get(name) or []
            if vals and vals[0].strip().isdigit():
                return str(int(vals[0]) + 1)
        m = re.search(r"/(\d+)(?:/)?$", parts.path)
        if m:
            return str(int(m.group(1)) + 1)
        return None

    def _persist_callback(self, cb, label: str) -> Observation:
        """回连也进证据库：body 进 CAS，一行 evidence，role=callback。"""
        body = cb.body or b""
        sha = self.probe.cas.put(body) if body else sha256_hex(b"")
        public_host = getattr(self.probe.oob, "public_host", "oob")
        request = CanonicalRequest(
            engagement_id=self.engagement_id,
            method="OOB",
            scheme="oob",
            host=public_host,
            port=0,
            raw_path="/t/%s" % cb.token,
            identity=cb.source_ip,
            param_path=None,
            payload_class="oob_url",
            side_effect_level="L0",
        )
        ev_id = compute_evidence_id(request.to_json(), sha, label)
        ev = Evidence(
            evidence_id=ev_id,
            engagement_id=self.engagement_id,
            label=label,
            identity=cb.source_ip,
            request=request,
            status=200,
            content_type="text/plain",
            body_sha256=sha,
            body_len=len(body),
            headers=(("X-Oob-Protocol", cb.protocol), ("X-Oob-Path", cb.path[:200])),
            sample_count=cb.count,
            timings_ms=(),
            ts_first=cb.ts,
            ts_last=cb.ts,
            request_blob="",
        )
        self.store.upsert_evidence(ev)
        return Observation(role="callback", evidence_id=ev_id, identity=cb.source_ip,
                           method="OOB", url="oob://%s/%s" % (cb.protocol, cb.token),
                           status=200, content_type="text/plain", body_sha256=sha,
                           body_len=len(body), body=body, source_ip=cb.source_ip,
                           protocol=cb.protocol, token=cb.token)

    @staticmethod
    def _strip_for(raw: Dict[str, Any], role: str) -> Dict[str, Tuple[str, ...]]:
        """按角色（baseline|probe）取出"该摘掉哪些头/参数"。

        CSRF 判定的全部新意就在这一步：**同一发请求，只少一个令牌**。
        两边都摘（apply=both）只能证明"两个坏请求都被拒"，证明不了令牌是不是放行条件。
        """
        cfg = (raw.get("probe") or {}).get("strip") or {}
        apply = str(cfg.get("apply") or "probe").lower()
        if apply != "both" and apply != role:
            return {"headers": (), "params": ()}
        return {"headers": tuple(cfg.get("headers") or ()),
                "params": tuple(cfg.get("params") or ())}

    @staticmethod
    def _merge_ids(seq) -> List[str]:
        out: List[str] = []
        for i in seq:
            if i and i not in out:
                out.append(i)
        return out

    def _judge(self, raw: Dict[str, Any], label: str, roles: Dict[str, str],
               extra: Optional[List[Observation]] = None,
               burst_statuses: Tuple[int, ...] = (),
               burst_labels: Tuple[str, ...] = ()):
        name = raw["oracle"]["name"]
        cls = ORACLE_REGISTRY.get(name)
        if cls is None:
            raise VhxInvalid("oracle 未注册：%s" % name)
        obs = load_observations(self.store, self.probe.cas, self.engagement_id, label, roles)
        for lbl in burst_labels:
            obs = list(obs) + load_observations(self.store, self.probe.cas,
                                                self.engagement_id, lbl, roles)
        if extra:
            obs = list(obs) + list(extra)
        if burst_statuses:
            # 并发的 N 发是 N 条独立证据（label 带 #i），但 oracle 只该看一条。
            # 把状态序列挂到 probe 那条上，其余证据留在 finding.evidence_ids 里可追溯。
            obs = [replace(o, burst_statuses=tuple(burst_statuses))
                   if roles.get(o.evidence_id) == "probe" else o for o in obs]
        if not obs:
            return None
        return cls().run(obs, cls.Args(**(raw["oracle"].get("args") or {})))

    def _verdict_json(self, v: Verdict) -> Dict[str, Any]:
        # oracle 想改标题（比如"敏感文件"实际命中的是 Java 堆栈）只能通过这里带出去，
        # 否则 _finalize 只会照抄模板标题，报告上就是张冠李戴。
        out: Dict[str, Any] = {"metrics": v.metrics, "rationale": v.rationale}
        if v.title:
            out["title"] = v.title
        return out

    def _finalize(self, raw: Dict[str, Any], evidence_ids: List[str], confidence: float,
                  verdict: Dict[str, Any], stop: str, used: int,
                  roles: Optional[Dict[str, str]] = None) -> Finding:
        # 通道消歧的结论必须跟着结论一起落库：操作者要能看到"这次是三档都通、
        # 还是换了浏览器档才通"，否则"被拦"与"没洞"在报告上长得一样。
        verdict = dict(verdict or {})
        if roles:
            # 角色表也落库：一条 finding 挂着 3~4 条证据，事后要能说清
            # "哪一发是带载荷的 probe"（`pta show` 就是靠它挑请求还原成 PoC）。
            # 不落库的话只能靠 payload_class/identity 猜，猜错就把 baseline 当成了 PoC。
            verdict["roles"] = dict(sorted(roles.items()))
        if self._net_error and not evidence_ids and stop in ("", "no_verdict"):
            stop = "unreachable"
        if self._channel_report is not None:
            metrics = dict(verdict.get("metrics") or {})
            metrics["channel"] = self._channel_report.to_json()
            verdict["metrics"] = metrics
            for eid in self._channel_report.evidence_ids:
                if eid not in evidence_ids:
                    evidence_ids.append(eid)
        # 等审批不是"没发现问题"，是"还没开始打"。状态必须自己说出来，
        # 否则面板上会显示成一条 0 分的 refuted，操作者会以为模板判否了。
        if stop.startswith("pending_approval"):
            status = "pending_approval"
        elif stop.startswith(("channel_blocked", "channel_unverified")):
            # "被拦住了"既不是"有洞"也不是"没洞"：0.5 的置信度在阈值表里落在
            # refuted 区间（<0.60），必须显式抬成 hypothesis，否则面板会显示"已否定"。
            status = "hypothesis"
        elif self._net_error and not evidence_ids:
            # 一次都没出网成功，同样是"没跑成"：不能因为 0 分就落成"已否定"。
            status = "hypothesis"
        else:
            status = verdict_status(confidence)
        f = Finding(
            id=finding_id(raw["id"], evidence_ids),
            engagement_id=self.engagement_id,
            template_id=raw["id"],
            title=verdict.get("title") or raw["title"],
            status=status,
            confidence=confidence,
            evidence_ids=evidence_ids,
            verdict=verdict,
            stop_reason=stop,
            requests_used=used,
        )
        self.store.put_finding({
            "id": f.id, "engagement_id": f.engagement_id, "template_id": f.template_id,
            "title": f.title, "status": f.status, "confidence": f.confidence,
            "evidence_ids": f.evidence_ids, "verdict": f.verdict, "created_at": _now(),
        })
        self.store.log_action(
            engagement_id=self.engagement_id, tool="executor", decision="finding",
            reason=stop, url="", level=raw["side_effect_level"],
            detail={"finding_id": f.id, "status": f.status, "confidence": f.confidence,
                    "evidence_ids": f.evidence_ids, "requests_used": used},
        )
        if self.probe.bus is not None:
            self.probe.bus.publish({"type": "finding", "id": f.id, "template": f.template_id,
                                    "status": f.status, "confidence": f.confidence})
        return f
