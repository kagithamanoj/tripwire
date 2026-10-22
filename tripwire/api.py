"""Transport-independent HTTP API shared by the local server and the AWS Lambda handler."""

import hmac
import json

from . import arena
from .detector import scan
from .gateway import Gateway
from .receipts import ReceiptLog, verify
from .review import ReviewQueue
from .sandbox import run_scenario
from .ui import PAGE
from .utility import run_utility

MAX_BODY = 64 * 1024
MAX_TEXT = 20_000
REVIEW_TTL_S = 900.0
_cache: dict = {}
_HEADERS = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}


def _json(obj, code: int = 200):
    return code, json.dumps(obj).encode(), "application/json"


def _cached(name, fn):
    if name not in _cache:
        _cache[name] = fn()
    return _cache[name]


def _authorized(headers: dict | None, approver_token: str | None) -> bool:
    given = (headers or {}).get("x-approver-token", "")
    return bool(approver_token) and hmac.compare_digest(given.encode(), approver_token.encode())


def handle(method: str, path: str, body: bytes = b"", log_factory=ReceiptLog, session_loader=None,
           reviews=None, approver_token: str | None = None, headers: dict | None = None):
    """Return (status, body_bytes, content_type).

    log_factory builds the receipt log per request; session_loader(session_id) -> (receipts, signer)
    lets the API re-verify stored sessions and append human decisions to them. `reviews` is a store
    with put/get/pending (memory or DynamoDB); approver endpoints need `approver_token`.
    """
    path = path.split("?")[0]
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if method == "GET":
        if path == "/":
            return 200, PAGE.encode(), "text/html; charset=utf-8"
        if path == "/healthz":
            return _json({"ok": True})
        if path == "/api/arena":
            return _json(_cached("arena", arena.run_arena))
        if path == "/api/utility":
            return _json(_cached("utility", run_utility))
        if path == "/api/samples":
            from . import corpus
            return _json({
                "attacks": [{"id": a["id"], "kind": a["kind"], "text": a["text"], "uses_tool": bool(a["harmful"])}
                            for a in corpus.ATTACKS],
                "benign": [{"id": b["id"], "text": b["text"]} for b in corpus.BENIGN],
            })
        if path.startswith("/api/session/") and session_loader:
            receipts, signer = session_loader(path.rsplit("/", 1)[1])
            if not receipts:
                return _json({"error": "unknown session"}, 404)
            ok, bad = verify(receipts, signer)
            return _json({"receipts": len(receipts), "verified": ok, "first_bad_seq": bad})
        if path == "/api/reviews" and reviews and approver_token:
            if not _authorized(headers, approver_token):
                return _json({"error": "approver token required"}, 401)
            return _json({"pending": sorted(reviews.pending(), key=lambda i: i["created"])})
    elif method == "POST" and path.startswith("/api/reviews/") and reviews and approver_token:
        return _decide(path.rsplit("/", 1)[1], body, headers, log_factory, session_loader, reviews, approver_token)
    elif method == "POST" and path == "/api/try":
        if len(body) > MAX_BODY:
            return _json({"error": "body too large"}, 413)
        try:
            req = json.loads(body)
            text = str(req["text"])[:MAX_TEXT]
            task = str(req.get("task", "Summarize the document."))[:500]
            tamper = req.get("tamper") is True
            mode = req.get("taint_mode", "session")
            if mode not in ("session", "value"):
                raise ValueError(mode)
        except (ValueError, KeyError, TypeError):
            return _json({"error": "expected JSON {text, task?, taint_mode?: session|value}"}, 400)
        unprotected, _ = run_scenario(text, task)
        queue = ReviewQueue(REVIEW_TTL_S, sink=reviews.put if reviews else None)
        gw = Gateway(log=log_factory(), queue=queue, taint_mode=mode)
        protected, stats = run_scenario(text, task, gateway=gw)
        res = scan(text)
        ok, bad = gw.log.verify()
        shown = [{"seq": r["seq"], "event": dict(r["event"]), "sig": r["sig"][:16]} for r in gw.log.receipts]
        tamper_check = None
        if tamper and gw.log.receipts:  # edit the in-memory copy only; nothing stored is touched
            first = gw.log.receipts[0]["event"]
            before = first.get("action")
            first["action"] = "allow" if before != "allow" else "block"
            t_ok, t_bad = gw.log.verify()
            tamper_check = {"verified": t_ok, "first_bad_seq": t_bad, "edited_seq": 0,
                            "field": "action", "from": before, "to": first["action"]}
        return _json({
            "detector": {"action": res.action, "score": res.score, "rules": [f.rule for f in res.findings]},
            "unprotected_executed": unprotected.executed,
            "protected_executed": protected.executed,
            "held_for_human": stats["reviews"], "blocked": stats["blocked"],
            "review_ids": [i["id"] for i in gw.queue.pending()],
            "session": gw.log.session_id, "chain_verified": ok,
            "receipts": shown, "tamper_check": tamper_check,
        })
    return _json({"error": "not found"}, 404)


def _decide(rid, body, headers, log_factory, session_loader, reviews, approver_token):
    if not _authorized(headers, approver_token):
        return _json({"error": "approver token required"}, 401)
    if len(body) > MAX_BODY:
        return _json({"error": "body too large"}, 413)
    try:
        req = json.loads(body)
        approve = req["approve"]
        reviewer = str(req.get("reviewer", "approver"))[:80]
        note = str(req.get("note", ""))[:300]
        if not isinstance(approve, bool):
            raise ValueError("approve must be boolean")
    except (ValueError, KeyError, TypeError):
        return _json({"error": "expected JSON {approve: bool, reviewer?, note?}"}, 400)
    item = reviews.get(rid)
    if item is None:
        return _json({"error": "unknown review"}, 404)
    queue = ReviewQueue.around(item, REVIEW_TTL_S, sink=reviews.put)
    try:
        decided = queue.decide(rid, approve, reviewer, note)
    except ValueError as e:  # already decided, or timed out and therefore denied
        return _json({"error": str(e), "status": queue.items[rid]["status"]}, 409)
    session = (item.get("payload") or {}).get("session")
    if session and session_loader:  # record the human decision in the original signed chain
        receipts, signer = session_loader(session)
        if receipts:
            log = ReceiptLog.resume(receipts, session, signer=signer, sink=log_factory().sink)
            log.append({"type": "human", "review_id": rid, "status": decided["status"], "by": reviewer})
    return _json({"id": rid, "status": decided["status"], "decided_by": reviewer})


def security_headers() -> dict:
    return dict(_HEADERS)
