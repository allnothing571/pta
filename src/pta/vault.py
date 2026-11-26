"""凭证仓。秘密只在内存里被 resolve 成真实值，落盘只有哈希与引用。"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional


class Vault:
    def __init__(self, path: str):
        self.path = path
        self._data: Dict[str, str] = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                self._data = json.load(fh)

    def put(self, ref: str, value: str) -> None:
        self._data[ref] = value
        self._flush()

    def get(self, ref: str) -> Optional[str]:
        return self._data.get(ref)

    def require(self, ref: str) -> str:
        val = self._data.get(ref)
        if val is None:
            raise KeyError("凭证缺失：%s" % ref)
        return val

    # ---------- 身份（cred/<identity>/<header>） ----------
    def refs(self, prefix: str = "") -> List[str]:
        return sorted(r for r in self._data if r.startswith(prefix))

    def items(self, prefix: str = "") -> Dict[str, str]:
        return {r: self._data[r] for r in self.refs(prefix)}

    def delete(self, ref: str) -> bool:
        if ref not in self._data:
            return False
        del self._data[ref]
        self._flush()
        return True

    def identities(self, prefix: str = "cred/") -> List[str]:
        found = set()
        for ref in self._data:
            if not ref.startswith(prefix):
                continue
            rest = ref[len(prefix):]
            if "/" in rest:
                found.add(rest.split("/", 1)[0])
        return sorted(found)

    def _flush(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, ensure_ascii=False)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

