"""Human-override queue. Unanswered items expire to DENY (fail closed)."""

import secrets
import time


class MemoryReviewStore:
    """Process-local store with the same interface as aws_store.DynamoReviewStore."""

    def __init__(self):
        self.data: dict[str, dict] = {}

    def put(self, item: dict) -> None:
        self.data[item["id"]] = dict(item)

    def get(self, rid: str) -> dict | None:
        return dict(self.data[rid]) if rid in self.data else None

    def pending(self) -> list[dict]:
        return [dict(i) for i in self.data.values() if i["status"] == "pending"]


class ReviewQueue:
    def __init__(self, ttl_s: float = 900.0, sink=None):
        """sink: optional callable(item) invoked whenever an item is created or changes."""
        self.ttl_s = ttl_s
        self.sink = sink
        self.items: dict[str, dict] = {}

    def _persist(self, item: dict) -> None:
        if self.sink:
            self.sink(item)

    @classmethod
    def around(cls, item: dict, ttl_s: float = 900.0, sink=None) -> "ReviewQueue":
        """A queue holding one stored item, so it can be decided on later (e.g. in another Lambda)."""
        q = cls(ttl_s, sink)
        q.items[item["id"]] = dict(item)
        return q

    def submit(self, kind: str, payload: dict, reason: str, now: float | None = None) -> str:
        rid = f"R{secrets.token_hex(6)}"  # unguessable and unique across Lambda containers
        self.items[rid] = {
            "id": rid, "kind": kind, "payload": payload, "reason": reason,
            "created": now if now is not None else time.time(), "status": "pending",
        }
        self._persist(self.items[rid])
        return rid

    def expire(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        n = 0
        for it in self.items.values():
            if it["status"] == "pending" and now - it["created"] > self.ttl_s:
                it["status"], it["decided_by"] = "denied", "timeout"
                self._persist(it)
                n += 1
        return n

    def pending(self) -> list[dict]:
        return [i for i in self.items.values() if i["status"] == "pending"]

    def decide(self, rid: str, approve: bool, reviewer: str, note: str = "") -> dict:
        it = self.items[rid]
        self.expire()  # an item that timed out can no longer be approved
        if it["status"] != "pending":
            raise ValueError(f"{rid} already {it['status']}")
        it.update(status="approved" if approve else "denied", decided_by=reviewer, note=note)
        self._persist(it)
        return it
