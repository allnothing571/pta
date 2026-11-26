"""证据复现。

两个用途：
1. 验收②：证据存下后能原样重放，且 CAS 被篡改时报 EvidenceCorrupted
2. 运维：目标变了（响应哈希不一致）时标记 stale，而不是悄悄改结论
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .cas import Cas
from .errors import EvidenceCorrupted, EvidenceNotFound
from .models import CanonicalRequest, ResolvedRequest, sha256_hex
from .scope import DnsPin, Scope, check_request
from .store import Store
from .transport import Transport, TransportError
from .vault import Vault


class Replayer:
    def __init__(self, scope: Scope, store: Store, cas: Cas, transport: Transport,
                 vault: Vault, dns: Optional[DnsPin] = None):
        self.scope = scope
        self.store = store
        self.cas = cas
        self.transport = transport
        self.vault = vault
        self.dns = dns or DnsPin()

    def replay(self, evidence_id: str, timeout_s: float = 10.0) -> Dict[str, Any]:
        row = self.store.get_evidence_row(evidence_id)
        if row is None:
            raise EvidenceNotFound(evidence_id)

        # 先验证证据本身没被改过
        stored_body = self.cas.get(row["body_sha256"])
        if sha256_hex(stored_body) != row["body_sha256"]:
            raise EvidenceCorrupted("响应体哈希不一致：%s" % evidence_id)

        req_json = json.loads(self.cas.get(row["request_blob"]).decode("utf-8"))
        canonical = CanonicalRequest.from_json(req_json)

        host, scheme, port, path = check_request(
            self.scope, canonical.method, canonical.url(), canonical.side_effect_level
        )
        pinned = self.dns.pin(host, self.scope)
        resolved = self._resolve(canonical, pinned)

        try:
            resp = self.transport.send(resolved, timeout_s=timeout_s)
        except TransportError as exc:
            self.store.log_action(self.scope.engagement_id, "replay", "error", str(exc),
                                  host=host, url=canonical.url())
            return {"evidence_id": evidence_id, "match": False, "stale": None,
                    "error": "transport: %s" % exc}

        new_sha = sha256_hex(resp.body)
        match = new_sha == row["body_sha256"] and resp.status == int(row["status"])
        result = {
            "evidence_id": evidence_id,
            "match": match,
            "stale": (not match),
            "expected_sha256": row["body_sha256"],
            "actual_sha256": new_sha,
            "expected_status": int(row["status"]),
            "actual_status": resp.status,
        }
        self.store.log_action(
            self.scope.engagement_id, "replay",
            "ok" if match else "stale",
            "" if match else "响应与证据不一致",
            host=host, url=canonical.url(), detail=result,
        )
        return result

    def _resolve(self, canonical: CanonicalRequest, pinned: str) -> ResolvedRequest:
        headers = []
        for h in canonical.headers:
            if h.kind == "vault_ref" and h.ref:
                value = self.vault.require(h.ref)
            elif h.kind == "derived":
                value = h.value or canonical.host
            else:
                value = h.value or ""
            headers.append((h.name, value))
        body = b""
        if canonical.body.blob:
            body = self.cas.get(canonical.body.blob)
        return ResolvedRequest(
            method=canonical.method, scheme=canonical.scheme, host=canonical.host,
            port=canonical.port, raw_path=canonical.raw_path, query=canonical.query,
            headers=tuple(headers), body=body, pinned_ip=pinned,
        )
