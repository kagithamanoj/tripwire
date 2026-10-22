"""Transport-independent HTTP API shared by the local server and the AWS Lambda handler."""

import json

from . import arena
from .detector import scan
from .gateway import Gateway
from .receipts import ReceiptLog, verify
from .sandbox import run_scenario
from .ui import PAGE
from .utility import run_utility

MAX_BODY = 64 * 1024
MAX_TEXT = 20_000
_cache: dict = {}
_HEADERS = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}


def _json(obj, code: int = 200):
    return code, json.dumps(obj).encode(), "application/json"


def _cached(name, fn):
    if name not in _cache:
        _cache[name] = fn()
    return _cache[name]


def handle(method: str, path: str, body: bytes = b"", log_factory=ReceiptLog, session_loader=None):
    """Return (status, body_bytes, content_type). log_factory builds the receipt log per request;
    session_loader(session_id) -> (receipts, signer) lets the API re-verify stored sessions."""
    path = path.split("?")[0]
    if method == "GET":
        if path == "/":
            return 200, PAGE.encode(), "text/html; charset=utf-8"
        if path == "/healthz":
            return _json({"ok": True})
        if path == "/api/arena":
            return _json(_cached("arena", arena.run_arena))
        if path == "/api/utility":
            return _json(_cached("utility", run_utility))
        if path.startswith("/api/session/") and session_loader:
            receipts, signer = session_loader(path.rsplit("/", 1)[1])
            if not receipts:
                return _json({"error": "unknown session"}, 404)
            ok, bad = verify(receipts, signer)
            return _json({"receipts": len(receipts), "verified": ok, "first_bad_seq": bad})
    elif method == "POST" and path == "/api/try":
        if len(body) > MAX_BODY:
            return _json({"error": "body too large"}, 413)
        try:
            req = json.loads(body)
            text = str(req["text"])[:MAX_TEXT]
            task = str(req.get("task", "Summarize the document."))[:500]
            mode = req.get("taint_mode", "session")
            if mode not in ("session", "value"):
                raise ValueError(mode)
        except (ValueError, KeyError, TypeError):
            return _json({"error": "expected JSON {text, task?, taint_mode?: session|value}"}, 400)
        unprotected, _ = run_scenario(text, task)
        gw = Gateway(log=log_factory(), taint_mode=mode)
        protected, stats = run_scenario(text, task, gateway=gw)
        res = scan(text)
        ok, bad = gw.log.verify()
        return _json({
            "detector": {"action": res.action, "score": res.score, "rules": [f.rule for f in res.findings]},
            "unprotected_executed": unprotected.executed,
            "protected_executed": protected.executed,
            "held_for_human": stats["reviews"], "blocked": stats["blocked"],
            "session": gw.log.session_id, "chain_verified": ok,
            "receipts": [{"seq": r["seq"], "event": r["event"], "sig": r["sig"][:16]} for r in gw.log.receipts],
        })
    return _json({"error": "not found"}, 404)


def security_headers() -> dict:
    return dict(_HEADERS)
