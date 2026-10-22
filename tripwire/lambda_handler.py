"""AWS Lambda entry point (Function URL, payload format v2).

Env: KMS_KEY_ID (receipt signing key) and TABLE_NAME (DynamoDB). Without them it
falls back to in-memory HMAC receipts, so the same code runs unconfigured.
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
    if key and table:
        from .aws_store import DynamoSink, KmsSigner

        _state.update(signer=KmsSigner(key), sink=DynamoSink(table))
    else:
        _state.update(signer=None, sink=None)
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
    code, payload, ctype = api.handle(method, path, raw, log_factory, loader)
    return _resp(code, payload, ctype)
