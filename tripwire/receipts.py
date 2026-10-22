"""Signed, hash-chained safety receipts: tamper-evident evidence for every decision.

Local mode signs with HMAC-SHA256. On AWS the Signer can be swapped for KMS
(same interface: sign(hex) -> str).
"""

import hashlib
import hmac
import json
import os
import secrets
import time

GENESIS = "0" * 64


class HmacSigner:
    def __init__(self, key: bytes | None = None):
        env = os.environ.get("TRIPWIRE_SIGNING_KEY")
        # Ephemeral key if none is configured; never written to disk or logs.
        self.key = key or (env.encode() if env else secrets.token_bytes(32))

    def sign(self, digest_hex: str) -> str:
        return hmac.new(self.key, digest_hex.encode(), hashlib.sha256).hexdigest()

    def check(self, digest_hex: str, sig: str) -> bool:
        return hmac.compare_digest(sig, self.sign(digest_hex))


def _digest(prev: str, core: dict) -> str:
    return hashlib.sha256((prev + json.dumps(core, sort_keys=True)).encode()).hexdigest()


class ReceiptLog:
    def __init__(self, path: str | None = None, signer=None, sink=None):
        """signer: object with sign(hex)/check(hex, sig). sink: optional callable(session_id, receipt)
        used to persist each receipt (e.g. DynamoDB)."""
        self.path = path
        self.signer = signer or HmacSigner()
        self.sink = sink
        self.session_id = secrets.token_hex(8)
        self.receipts: list[dict] = []

    def verify(self) -> tuple[bool, int | None]:
        return verify(self.receipts, self.signer)

    @classmethod
    def resume(cls, receipts: list[dict], session_id: str, signer=None, sink=None) -> "ReceiptLog":
        """Continue an existing signed chain (e.g. to record a later human decision)."""
        log = cls(signer=signer, sink=sink)
        log.session_id = session_id
        log.receipts = list(receipts)
        return log

    def append(self, event: dict) -> dict:
        prev = self.receipts[-1]["hash"] if self.receipts else GENESIS
        core = {"seq": len(self.receipts), "ts": round(time.time(), 3), "event": event}
        digest = _digest(prev, core)
        receipt = {**core, "prev": prev, "hash": digest, "sig": self.signer.sign(digest)}
        self.receipts.append(receipt)
        if self.sink:
            self.sink(self.session_id, receipt)
        if self.path:
            with open(self.path, "a") as fh:
                fh.write(json.dumps(receipt, sort_keys=True) + "\n")
        return receipt


def verify(receipts: list[dict], signer) -> tuple[bool, int | None]:
    """Return (ok, first_bad_seq)."""
    prev = GENESIS
    for i, r in enumerate(receipts):
        core = {"seq": r["seq"], "ts": r["ts"], "event": r["event"]}
        digest = _digest(prev, core)
        if r["seq"] != i or r["prev"] != prev or r["hash"] != digest:
            return False, i
        if not signer.check(digest, r["sig"]):
            return False, i
        prev = digest
    return True, None


def load(path: str) -> list[dict]:
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]
