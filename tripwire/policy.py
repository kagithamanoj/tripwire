"""Layer 2: structural tool policy. Works even when the detector is fooled.

Core rule (taint tracking): once an agent has read untrusted content, any
risky action it takes is treated as possibly attacker-influenced.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

RISK = {
    "read_file": "low", "search_web": "low", "summarize": "low",
    "send_email": "high", "http_post": "high",
    "run_shell": "critical", "delete_file": "critical", "transfer_funds": "critical",
}
EGRESS_ARG = {"send_email": "to", "http_post": "url"}

SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("api_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("password_assignment", re.compile(r"(?i)password\s*[=:]\s*\S+")),
]


@dataclass
class Decision:
    action: str  # allow | review | block
    reason: str
    risk: str = "unknown"
    review_id: str | None = None


@dataclass
class Policy:
    tools: dict = field(default_factory=lambda: dict(RISK))
    egress_allowlist: tuple = ("acme.example",)

    def host_allowed(self, host: str) -> bool:
        host = (host or "").lower()
        return any(host == d or host.endswith("." + d) for d in self.egress_allowlist)

    def decide(self, tool: str, args: dict, tainted: bool) -> Decision:
        risk = self.tools.get(tool)
        if risk is None:
            return Decision("block", "unknown tool (default deny)")
        blob = " ".join(str(v) for v in args.values())
        for name, rx in SECRET_PATTERNS:
            if rx.search(blob):
                return Decision("block", f"secret in arguments ({name})", risk)
        arg = EGRESS_ARG.get(tool)
        if arg:
            host = _host_of(str(args.get(arg, "")))
            if not self.host_allowed(host):
                if tainted:
                    return Decision("block", f"tainted egress to non-allowlisted host {host!r}", risk)
                return Decision("review", f"external destination {host!r} needs approval", risk)
        if risk == "low":
            return Decision("allow", "low-risk tool", risk)
        if risk == "high":
            if tainted:
                return Decision("review", "high-risk action after untrusted input", risk)
            return Decision("allow", "high-risk action, clean context", risk)
        if tainted:
            return Decision("block", "critical action after untrusted input", risk)
        return Decision("review", "critical action always needs a human", risk)


def _host_of(value: str) -> str:
    value = value.strip()
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[1].strip(">").lower()
    return (urlparse(value).hostname or "").lower()


def redact(text: str) -> tuple[str, int]:
    count = 0
    for name, rx in SECRET_PATTERNS:
        text, n = rx.subn(f"[REDACTED:{name}]", text)
        count += n
    return text, count
