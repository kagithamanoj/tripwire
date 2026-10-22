"""Human-override queue. Unanswered items expire to DENY (fail closed)."""

import itertools
import time

_ids = itertools.count(1)


class ReviewQueue:
    def __init__(self, ttl_s: float = 900.0):
        self.ttl_s = ttl_s
        self.items: dict[str, dict] = {}

    def submit(self, kind: str, payload: dict, reason: str, now: float | None = None) -> str:
        rid = f"R{next(_ids):04d}"
        self.items[rid] = {
            "id": rid, "kind": kind, "payload": payload, "reason": reason,
            "created": now if now is not None else time.time(), "status": "pending",
        }
        return rid

    def expire(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        n = 0
        for it in self.items.values():
            if it["status"] == "pending" and now - it["created"] > self.ttl_s:
                it["status"], it["decided_by"] = "denied", "timeout"
                n += 1
        return n

    def pending(self) -> list[dict]:
        return [i for i in self.items.values() if i["status"] == "pending"]

    def decide(self, rid: str, approve: bool, reviewer: str, note: str = "") -> dict:
        it = self.items[rid]
        if it["status"] != "pending":
            raise ValueError(f"{rid} already {it['status']}")
        it.update(status="approved" if approve else "denied", decided_by=reviewer, note=note)
        return it
