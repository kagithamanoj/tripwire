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
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}")),
    ("api_key", re.compile(r"sk-[A-Za-z0-9_\-]{20,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
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
        host = (host or "").lower().rstrip(".")
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
            bad = [h for h in hosts_of(str(args.get(arg, ""))) if not self.host_allowed(h)]
            if bad:
                host = bad[0]
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


_URL = re.compile(r"(?:[a-z][a-z0-9+.\-]*:)?//[^\s\"'<>]+", re.I)
_EMAIL = re.compile(r"[\w.+'\-]+@([\w.\-]+)")


def hosts_of(value: str) -> list[str]:
    """Every destination host mentioned in a value (all emails and URLs). Empty value -> [''] (deny)."""
    hosts = []
    for m in _URL.finditer(value):
        url = m.group(0)
        if url.startswith("//"):  # scheme-relative
            url = "http:" + url
        hosts.append((urlparse(url).hostname or "").lower())
    for m in _EMAIL.finditer(_URL.sub(" ", value)):
        hosts.append(m.group(1).lower())
    return hosts or [""]


_EMAIL_ATOM = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
_URL_ATOM = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s\"'<>()\[\]{},;]+", re.I)
_PATH_ATOM = re.compile(r"(?<![\w:/.])/?[\w.\-]+(?:/[\w.\-]+)+")
_CODE_ATOM = re.compile(r"\b(?=[A-Za-z0-9\-]*[A-Za-z])(?=[A-Za-z0-9\-]*\d)[A-Za-z0-9][A-Za-z0-9\-]{3,}\b")


def atoms(text: str) -> set[str]:
    """Identifier-like values used for provenance tracking: emails, URLs, paths, and codes that
    mix letters and digits (e.g. ACC-9921).

    Plain words, words followed by a colon ("Notes:"), and bare numbers are NOT identifiers:
    tracking them would taint every summary that repeats a word from the document.
    """
    from .normalize import decode_embedded, normalize

    clean, _ = normalize(text)
    found = set()
    for chunk in [clean] + [normalize(d)[0] for d in decode_embedded(clean)]:
        for rx in (_EMAIL_ATOM, _URL_ATOM, _PATH_ATOM, _CODE_ATOM):
            for m in rx.finditer(chunk):
                tok = m.group(0).strip(".:!?").lower()
                if len(tok) >= 4:
                    found.add(tok)
    return found


def redact(text: str) -> tuple[str, int]:
    count = 0
    for name, rx in SECRET_PATTERNS:
        text, n = rx.subn(f"[REDACTED:{name}]", text)
        count += n
    return text, count
