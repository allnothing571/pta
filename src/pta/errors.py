"""P0 错误类型。所有拒绝都必须可捕获、可记录，不允许裸 Exception。"""


class PtaError(Exception):
    """所有 PTA 错误的基类。"""


class ScopeViolation(PtaError):
    """目标不在授权范围内。"""


class DnsPinViolation(ScopeViolation):
    """解析结果越界或不是可路由的公网地址。"""


class BudgetExceeded(PtaError):
    """请求预算耗尽或熔断触发。"""


class ApprovalRequired(PtaError):
    """L2+ 动作缺少有效审批。"""


class PayloadRejected(PtaError):
    """载荷类不存在或模型给出的原文不合法。"""


class EvidenceCorrupted(PtaError):
    """CAS 内容哈希与 manifest 不一致。"""


class EvidenceNotFound(PtaError):
    """证据不存在。"""


class VhxInvalid(PtaError):
    """模板加载期校验失败。"""
