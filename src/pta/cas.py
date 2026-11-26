"""内容寻址存储（CAS）+ 链式 manifest。

- 布局：cas/bodies/<aa>/<bb>/<sha256>.enc
- 读取时重算哈希，不一致抛 EvidenceCorrupted（验收②）
- 加密可插拔：有 cryptography 就用 AES-GCM，否则退化为 NullCipher（启动横幅告警）
"""
from __future__ import annotations

import hashlib
import threading
import hmac
import json
import os
import time
from datetime import datetime
from typing import Dict, Optional

from .errors import EvidenceCorrupted


class Cipher:
    name = "abstract"

    def encrypt(self, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, blob: bytes) -> bytes:
        raise NotImplementedError


class NullCipher(Cipher):
    """仅用于本地靶场/测试：明文落盘，文件名以 .enc 结尾是刻意的自欺式占位。"""

    name = "null-plaintext"

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext

    def decrypt(self, blob: bytes) -> bytes:
        return blob


class AesGcmCipher(Cipher):
    name = "aes-256-gcm"
    NONCE_LEN = 12

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("key 必须是 32 字节")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # 延迟导入

        self._aead = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(self.NONCE_LEN)
        return nonce + self._aead.encrypt(nonce, plaintext, None)

    def decrypt(self, blob: bytes) -> bytes:
        nonce, ct = blob[: self.NONCE_LEN], blob[self.NONCE_LEN :]
        return self._aead.decrypt(nonce, ct, None)


def default_cipher(secret_path: Optional[str] = None) -> Cipher:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except Exception:
        return NullCipher()
    key_path = secret_path or os.path.join(os.getcwd(), ".pta", "master.key")
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if os.path.exists(key_path):
        with open(key_path, "rb") as fh:
            key = fh.read()
    else:
        key = os.urandom(32)
        with open(key_path, "wb") as fh:
            fh.write(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return AesGcmCipher(key)


class Manifest:
    """append-only jsonl，prev_hash 串联。删改中间行会让链断裂。"""

    def __init__(self, path: str):
        self.path = path
        self._last_hash = "0" * 64
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    self._last_hash = rec["hash"]

    def append(self, kind: str, ref: str, extra: Optional[Dict] = None) -> str:
        rec = {
            "kind": kind,
            "ref": ref,
            "ts": datetime.utcnow().isoformat() + "Z",
            "prev": self._last_hash,
            "extra": extra or {},
        }
        body = json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
        rec["hash"] = hashlib.sha256(body).hexdigest()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
        self._last_hash = rec["hash"]
        return rec["hash"]

    def verify(self) -> bool:
        if not os.path.exists(self.path):
            return True  # 空工作区视为链完整
        prev = "0" * 64
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                claimed = rec.pop("hash")
                body = json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
                if hashlib.sha256(body).hexdigest() != claimed or rec["prev"] != prev:
                    return False
                prev = claimed
        return True


class Cas:
    def __init__(self, root: str, cipher: Optional[Cipher] = None, manifest: Optional[Manifest] = None):
        self.root = os.path.abspath(root)
        self.cipher = cipher or NullCipher()
        os.makedirs(os.path.join(self.root, "bodies"), exist_ok=True)
        self.manifest = manifest or Manifest(os.path.join(self.root, "manifest.jsonl"))
        # manifest 是 prev_hash 链，并发 append 必须串行，否则链会分叉
        self._lock = threading.Lock()

    def path_for(self, sha: str) -> str:
        return os.path.join(self.root, "bodies", sha[:2], sha[2:4], sha + ".enc")

    def put(self, plaintext: bytes, kind: str = "body") -> str:
        sha = hashlib.sha256(plaintext).hexdigest()
        dest = self.path_for(sha)
        if os.path.exists(dest):
            return sha
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        blob = self.cipher.encrypt(plaintext)
        # 临时文件名必须唯一：并发跑多个候选时，两个线程会同时写同一份响应体
        # （同一 sha），共用 "dest.tmp" 在 Windows 上直接 PermissionError。
        tmp = "%s.%d-%d.tmp" % (dest, os.getpid(), threading.get_ident())
        with open(tmp, "wb") as fh:
            fh.write(blob)
        try:
            os.replace(tmp, dest)
        except OSError:
            # 另一个线程已经把它落盘了，内容按 sha 相同，直接收工
            try:
                os.unlink(tmp)
            except OSError:
                pass
        with self._lock:
            self.manifest.append(kind, sha, {"len": len(plaintext), "cipher": self.cipher.name})
        return sha

    def get(self, sha: str) -> bytes:
        dest = self.path_for(sha)
        if not os.path.exists(dest):
            raise EvidenceCorrupted("CAS 缺失：%s" % sha)
        blob = self._read(dest, sha)
        try:
            plain = self.cipher.decrypt(blob)
        except Exception as exc:
            raise EvidenceCorrupted("解密失败：%s (%s)" % (sha, exc))
        if hashlib.sha256(plain).hexdigest() != sha:
            raise EvidenceCorrupted("哈希不一致：%s" % sha)
        return plain

    @staticmethod
    def _read(dest: str, sha: str) -> bytes:
        """读一个 blob，容忍 Windows 的"文件正被替换"。

        并发突发（N 个线程写同一份请求体）时，一个线程正在 os.replace 落盘，
        另一个线程同时 open 会拿到 sharing violation —— 在 Windows 上表现为
        PermissionError。它只持续几毫秒，退避重试即可，不必上全局锁把读串行化。
        """
        last = None
        for attempt in range(6):
            try:
                with open(dest, "rb") as fh:
                    return fh.read()
            except PermissionError as exc:
                last = exc
                time.sleep(0.005 * (attempt + 1))
        raise EvidenceCorrupted("读 CAS 失败（文件被占用）：%s (%s)" % (sha, last))

    def exists(self, sha: str) -> bool:
        return os.path.exists(self.path_for(sha))

    def verify_manifest(self) -> bool:
        return self.manifest.verify()
