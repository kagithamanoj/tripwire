"""AWS Lambda entry point (Function URL, payload format v2).

Env: KMS_KEY_ID (receipt signing key) and TABLE_NAME (DynamoDB). Without them it
falls back to in-memory HMAC receipts, so the same code runs unconfigured.
"""

import base64
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


def handler(event, context=None):
    st = _setup()
    http = event["requestContext"]["http"]
    body = event.get("body") or ""
    raw = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()

    def log_factory():
        return ReceiptLog(signer=st["signer"], sink=st["sink"])

    loader = (lambda sid: (st["sink"].load(sid), st["signer"])) if st["sink"] else None
    code, payload, ctype = api.handle(http["method"], http["path"], raw, log_factory, loader)
    return {
        "statusCode": code,
        "headers": {"Content-Type": ctype, **api.security_headers()},
        "body": payload.decode(),
    }
