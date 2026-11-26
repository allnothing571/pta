"""PTA P0 —— 可执行的最小证据驱动渗透 Agent 骨架。"""
__version__ = "0.1.0"

from .errors import (ApprovalRequired, BudgetExceeded, DnsPinViolation, EvidenceCorrupted,
                     EvidenceNotFound, PayloadRejected, PtaError, ScopeViolation, VhxInvalid)
from .models import CanonicalRequest, Evidence, Extract, Verdict, verdict_status
from .probe import ProbeRequest, ProbeResult, ProbeTool

__all__ = [
    "PtaError", "ScopeViolation", "DnsPinViolation", "BudgetExceeded", "ApprovalRequired",
    "PayloadRejected", "EvidenceCorrupted", "EvidenceNotFound", "VhxInvalid",
    "CanonicalRequest", "Evidence", "Extract", "Verdict", "verdict_status",
    "ProbeTool", "ProbeRequest", "ProbeResult", "__version__",
]
