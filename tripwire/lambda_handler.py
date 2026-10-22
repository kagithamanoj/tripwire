"""AWS Lambda entry point (Function URL, payload format v2).

Env: KMS_KEY_ID (receipt signing key), TABLE_NAME (receipts), REVIEWS_TABLE (human-review items) and
APPROVER_SECRET_ARN (Secrets Manager secret holding the approver token). Without them it falls back to
in-memory HMAC receipts and disabled approvals, so the same code runs unconfigured.
"""

import base64
import logging
import os

from . import api
from .receipts import ReceiptLog

_state: dict = {}


def _setup():
    if _state:
        return _state
    key, table = os.environ.get("KMS_KEY_ID"), os.environ.get("TABLE_NAME")
    _state.update(signer=None, sink=None, reviews=None, token=None)
    if key and table:
        from .aws_store import DynamoSink, KmsSigner

        _state.update(signer=KmsSigner(key), sink=DynamoSink(table))
    rtable, secret = os.environ.get("REVIEWS_TABLE"), os.environ.get("APPROVER_SECRET_ARN")
    if rtable and secret:
        from .aws_store import DynamoReviewStore, get_secret

        _state.update(reviews=DynamoReviewStore(rtable), token=get_secret(secret))
    return _state


def _resp(code: int, payload: bytes, ctype: str = "application/json") -> dict:
    return {"statusCode": code, "headers": {"Content-Type": ctype, **api.security_headers()}, "body": payload.decode()}


def handler(event, context=None):
    try:
        http = event["requestContext"]["http"]
        method, path = http["method"], http["path"]
    except (KeyError, TypeError):
        return _resp(400, b'{"error": "unsupported event shape"}')
    try:
        return _handle(event, method, path)
    except Exception:  # never leak internals to the caller; details go to CloudWatch
        logging.getLogger().exception("unhandled error")
        return _resp(500, b'{"error": "internal error"}')


def _handle(event, method: str, path: str) -> dict:
    st = _setup()
    body = event.get("body") or ""
    try:
        raw = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()
    except ValueError:
        return _resp(400, b'{"error": "bad body encoding"}')

    def log_factory():
        return ReceiptLog(signer=st["signer"], sink=st["sink"])

    loader = (lambda sid: (st["sink"].load(sid), st["signer"])) if st["sink"] else None
    code, payload, ctype = api.handle(method, path, raw, log_factory, loader,
                                      reviews=st.get("reviews"), approver_token=st.get("token"),
                                      headers=event.get("headers") or {})
    return _resp(code, payload, ctype)
