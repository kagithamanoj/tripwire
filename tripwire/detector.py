"""Layer 1: heuristic injection detector. Useful signal, never the only defence."""

import re
from dataclasses import dataclass, field

from .normalize import decode_embedded, normalize

RULES = [
    ("override", "instruction_override",
     r"\b(ignore|disregard|forget|override)\b.{0,25}\b(previous|prior|above|earlier|all|any|your)\b.{0,25}\b(instructions?|prompts?|rules|guidelines|directives)\b", 0.8),
    ("role_hijack", "role_hijack",
     r"\b(you are now|from now on you are|act as (an? )?(unrestricted|jailbroken)|developer mode|dan mode)\b", 0.6),
    ("fake_system", "channel_spoofing",
     r"(^|\s)(system|assistant)\s*:|\[/?(system|inst)\]|<\|(im_start|im_end)\|>|</?system>", 0.55),
    ("exfil", "data_exfiltration",
     r"\b(send|forward|post|upload|email|exfiltrate|leak)\b.{0,60}\b(passwords?|secrets?|api[_ -]?keys?|credentials?|tokens?|\.env|ssh|private key)\b", 0.8),
    ("prompt_leak", "prompt_leak",
     r"\b(reveal|print|show|repeat|output|display)\b.{0,40}\b(system prompt|your instructions|hidden prompt|initial prompt)\b", 0.7),
    ("tool_directive", "tool_hijack",
     r"\b(send_email|delete_file|run_shell|http_post|transfer_funds)\s*\(", 0.7),
    ("md_exfil", "data_exfiltration",
     r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=", 0.7),
    ("secrecy", "concealment",
     r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|alert|notify)\b.{0,30}\b(user|human|operator)\b", 0.5),
    ("authority", "social_engineering",
     r"\b(admin|developer|administrator)\s+(override|message|mode|instruction)", 0.4),
]
_COMPILED = [(rid, cat, re.compile(rx, re.I), w) for rid, cat, rx, w in RULES]


@dataclass
class Finding:
    rule: str
    category: str
    weight: float
    excerpt: str


@dataclass
class ScanResult:
    score: float
    action: str  # allow | review | block
    findings: list = field(default_factory=list)
    flags: list = field(default_factory=list)


def _apply(text: str, prefix: str = "") -> list[Finding]:
    out = []
    for rid, cat, rx, w in _COMPILED:
        m = rx.search(text)
        if m:
            out.append(Finding(prefix + rid, cat, w, m.group(0)[:80]))
    return out


def scan(text: str, review_at: float = 0.4, block_at: float = 0.75) -> ScanResult:
    clean, flags = normalize(text)
    findings = _apply(clean)
    for decoded in decode_embedded(clean):
        inner, _ = normalize(decoded)
        findings += _apply(inner, "encoded:")
    if flags:
        findings.append(Finding("obfuscation", "evasion", 0.3, ",".join(flags)))
    if any(f.rule.startswith("encoded:") for f in findings):
        findings.append(Finding("hidden_payload", "evasion", 0.3, "base64 payload"))
    miss = 1.0
    for f in findings:
        miss *= 1 - f.weight
    score = round(1 - miss, 3)
    action = "block" if score >= block_at else "review" if score >= review_at else "allow"
    return ScanResult(score, action, findings, flags)
