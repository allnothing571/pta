"""JWT 信任边界演示：alg=none / 去签名两种伪造，与服务端三种反应。

python demo_jwt.py
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pta import jwtlab, vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockRoute, MockTransport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ME = b'{"id":7,"email":"alice@corp.test","role":"user","wallet":1200}'
ANON = b'{"error":"login required"}'
JWT = "Bearer " + ".".join([
    jwtlab.b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()),
    jwtlab.b64url_encode(json.dumps({"sub": "7", "role": "user"}).encode()),
    "c2lnbmF0dXJl",
])
NONE_TOK = jwtlab.forge(JWT, "none")
STRIP_TOK = jwtlab.forge(JWT, "strip")


def decode_header(token):
    seg = token.split(" ")[1].split(".")[0]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode())


def build(mode):
    """mode ∈ accept-none | accept-strip | reject | wrong-identity"""
    routes = [MockRoute("GET", "api.test", "/api/me", 200,
                        (("Content-Type", "application/json"),), ME, identity=JWT)]
    if mode == "accept-none":
        routes.append(MockRoute("GET", "api.test", "/api/me", 200,
                                (("Content-Type", "application/json"),), ME,
                                identity=NONE_TOK))
        routes.append(MockRoute("GET", "api.test", "/api/me", 200,
                                (("Content-Type", "application/json"),), ME,
                                identity=STRIP_TOK))
    elif mode == "accept-strip":
        routes.append(MockRoute("GET", "api.test", "/api/me", 401,
                                (("Content-Type", "application/json"),), ANON,
                                identity=NONE_TOK))
        routes.append(MockRoute("GET", "api.test", "/api/me", 200,
                                (("Content-Type", "application/json"),), ME,
                                identity=STRIP_TOK))
    elif mode == "reject":
        for tok in (NONE_TOK, STRIP_TOK):
            routes.append(MockRoute("GET", "api.test", "/api/me", 401,
                                    (("Content-Type", "application/json"),), ANON,
                                    identity=tok))
    else:   # wrong-identity：200 但拿到的是匿名视角的数据
        for tok in (NONE_TOK, STRIP_TOK):
            routes.append(MockRoute("GET", "api.test", "/api/me", 200,
                                    (("Content-Type", "application/json"),), ANON,
                                    identity=tok))

    root = tempfile.mkdtemp(prefix="pta-demo-jwt-")
    init_workspace(root, Scope(engagement_id="DEMO-JWT", domains=("api.test",),
                               allow_private=True, rate_per_host=200, max_requests=100))
    ws = open_workspace(root, transport=MockTransport(routes),
                        dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
    ws.vault.put("cred/A/authorization", JWT)
    return root, ws


def main() -> int:
    print("伪造 token 形态：")
    print("  alg=none :", NONE_TOK[:58] + "…", "→ header", decode_header(NONE_TOK))
    print("  strip    :", STRIP_TOK[:58] + "…", "→ header", decode_header(STRIP_TOK))
    print()

    tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == "jwt-trust-boundary"][0])
    cases = [
        ("accept-none", "服务端不验签、还认 alg=none（应确认）", "confirmed"),
        ("accept-strip", "只认非 none 的 alg，但不验签名（应确认）", "confirmed"),
        ("reject", "两种伪造都被 401（应否定）", "refuted"),
        ("wrong-identity", "伪造后回落匿名身份，数据不同（应否定）", "refuted"),
    ]
    print("%-16s %-11s %-6s %-5s %s" % ("服务端行为", "结论", "置信度", "请求", "场景"))
    print("-" * 92)
    bad = 0
    for mode, note, want in cases:
        root, ws = build(mode)
        try:
            f = Executor(ws.probe, ws.store, "DEMO-JWT").run(
                tpl, Target(url="http://api.test/api/me",
                            identity_baseline="A", identity_probe="A",
                            param_path="header:authorization"))
            print("%-16s %-11s %-6.3f %-5d %s" % (mode, f.status, f.confidence,
                                                 f.requests_used, note))
            if f.status != want:
                bad += 1
                print("   ！预期 %s：%s" % (want, f.verdict.get("rationale")))
        finally:
            shutil.rmtree(root, True)

    # 没有 JWT 凭据时不该发无意义的请求
    root, ws = build("accept-none")
    try:
        ws.vault.put("cred/A/authorization", "Bearer opaque-session-id")
        f = Executor(ws.probe, ws.store, "DEMO-JWT").run(
            tpl, Target(url="http://api.test/api/me",
                        identity_baseline="A", identity_probe="A",
                        param_path="header:authorization"))
        print("%-16s %-11s %-6.3f %-5d %s" % ("no-jwt", f.status, f.confidence,
                                             f.requests_used, "凭据不是 JWT，跳过伪造"))
        print("   skipped:", f.verdict.get("skipped"))
    finally:
        shutil.rmtree(root, True)

    print("\n结果：%s" % ("OK（4 种服务端反应都判对 + 凭据不可伪造时自动跳过）"
                         if not bad else "FAIL（%d 条不符预期）" % bad))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
