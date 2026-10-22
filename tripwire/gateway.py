"""The Tripwire gateway: scan inputs, authorise tool calls, filter outputs, sign everything."""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import detector
from .policy import Decision, Policy, redact
from .receipts import ReceiptLog
from .review import ReviewQueue

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")
BLOCKED = "[content blocked by Tripwire]"
HELD = "[content held for human review]"


@dataclass
class Ingest:
    action: str
    text: str
    score: float
    findings: list = field(default_factory=list)
    review_id: str | None = None


class Gateway:
    def __init__(self, policy=None, log=None, queue=None, use_detector=True, use_policy=True):
        self.policy = policy or Policy()
        self.log = log or ReceiptLog()
        self.queue = queue or ReviewQueue()
        self.use_detector = use_detector
        self.use_policy = use_policy
        self.tainted = False

    def ingest(self, text: str, source: str, trusted: bool = False) -> Ingest:
        """Scan content before the model sees it."""
        if trusted:
            self.log.append({"type": "ingest", "source": source, "action": "allow", "trusted": True})
            return Ingest("allow", text, 0.0)
        self.tainted = True  # structural: any untrusted read taints the session
        res = detector.scan(text) if self.use_detector else detector.ScanResult(0.0, "allow")
        rid = None
        if res.action == "review":
            rid = self.queue.submit("content", {"source": source, "excerpt": text[:120]}, "suspicious content")
        self.log.append({
            "type": "ingest", "source": source, "action": res.action, "score": res.score,
            "rules": [f.rule for f in res.findings], "review_id": rid,
        })
        shown = text if res.action == "allow" else BLOCKED if res.action == "block" else HELD
        return Ingest(res.action, shown, res.score, res.findings, rid)

    def authorize_tool(self, tool: str, args: dict, origin: str = "model") -> Decision:
        """origin='user' means the human typed the command directly (not tainted)."""
        tainted = self.tainted and origin != "user"
        if self.use_policy:
            d = self.policy.decide(tool, args, tainted)
        else:
            d = Decision("allow", "policy disabled", "unknown")
        if d.action == "review":
            d.review_id = self.queue.submit("tool", {"tool": tool, "args": args, "origin": origin}, d.reason)
        self.log.append({
            "type": "tool", "tool": tool, "origin": origin, "tainted": tainted,
            "action": d.action, "reason": d.reason, "risk": d.risk, "review_id": d.review_id,
        })
        return d

    def resolve(self, review_id: str, approve: bool, reviewer: str, note: str = "") -> dict:
        item = self.queue.decide(review_id, approve, reviewer, note)
        self.log.append({"type": "human", "review_id": review_id, "status": item["status"], "by": reviewer})
        return item

    def filter_output(self, text: str) -> str:
        """Redact secrets and strip image beacons to non-allowlisted hosts."""
        out, n = redact(text)

        def strip(m):
            host = urlparse(m.group(1)).hostname or ""
            return m.group(0) if self.policy.host_allowed(host) else "[image removed by Tripwire]"

        out2 = _MD_IMAGE.sub(strip, out)
        if n or out2 != out:
            self.log.append({"type": "output_filter", "redactions": n, "images_removed": out2 != out})
        return out2
