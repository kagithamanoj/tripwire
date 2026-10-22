"""Layer 1: heuristic injection detector. Useful signal, never the only defence."""

import re
from dataclasses import dataclass, field

from .normalize import normalize, scan_variants, squash, unfolded

MAX_SCAN_CHARS = 200_000  # larger inputs are held for review rather than scanned in part

_OVERRIDE_I18N = (
    r"ignora(?:r)?\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)"
    r"|ignor(?:e|ez)\s+(?:toutes\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)"
    r"|ignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|fr[uü]heren)\s+anweisungen"
    r"|ignore\s+(?:todas\s+)?as\s+instru[cç][oõ]es\s+(?:anteriores|pr[eé]vias)"
    r"|игнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие|прежние)\s+инструкции"
    r"|忽略.{0,6}(?:之前|以前|先前).{0,6}(?:指令|指示|说明)"
    r"|(?:以前|これまで|前)の(?:指示|命令).{0,8}無視"
)

RULES = [
    ("override", "instruction_override",
     r"\b(ignore|disregard|forget|override)\b.{0,25}\b(previous|prior|above|earlier|all|any|your)\b.{0,25}\b(instructions?|prompts?|rules|guidelines|directives)\b", 0.8),
    ("override_i18n", "instruction_override", _OVERRIDE_I18N, 0.8),
    ("role_hijack", "role_hijack",
     r"\b(you are now (in )?(dan|developer|god|unrestricted|unfiltered|jailbroken)\b|from now on you are|act as (an? )?(unrestricted|jailbroken)|dan mode|jailbreak(ed)?)", 0.6),
    ("chat_template", "channel_spoofing",
     r"\[/?(system|inst)\]|<\|(im_start|im_end)\|>|</?system>", 0.55),
    ("fake_system_line", "channel_spoofing",
     r"(^|\s)SYSTEM\s*:|(?m:^\s*(system|assistant)\s*:)", 0.3),
    ("exfil", "data_exfiltration",
     r"\b(send|forward|post|upload|email|exfiltrate|leak)\b.{0,60}\b(passwords?|secrets?|api[_ -]?keys?|credentials?|tokens?|\.env|ssh|private key)\b", 0.8),
    ("prompt_leak", "prompt_leak",
     r"\b(reveal|print|show|repeat|output|display)\b.{0,40}\b(system prompt|your instructions|hidden prompt|initial prompt)\b", 0.7),
    ("tool_directive", "tool_hijack",
     r"\b(send_email|delete_file|run_shell|http_post|transfer_funds)\s*\(", 0.7),
    ("md_exfil", "data_exfiltration",
     r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=", 0.7),
    ("secrecy", "concealment",
     r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|alert|notify)\b.{0,30}\b(user|human|operator)\b", 0.3),
    ("authority", "social_engineering",
     r"\b(admin|developer|administrator)\s+(override|message|instruction)", 0.3),
]
_COMPILED = [(rid, cat, re.compile(rx, re.I if rid != "fake_system_line" else 0), w) for rid, cat, rx, w in RULES]

# Rules re-checked on text with all spacing/punctuation removed (spaced, hyphenated, dotted letters).
_SQUASHED = [
    ("override", re.compile(r"(ignore|disregard|forget|override)(all|any|the)?(previous|prior|above|earlier|your)(instructions?|prompts?|rules|guidelines|directives)")),
    ("prompt_leak", re.compile(r"(reveal|print|show|repeat|output|display)(your|the)?(systemprompt|instructions|hiddenprompt|initialprompt)")),
]


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
    if len(text) > MAX_SCAN_CHARS:
        return ScanResult(0.5, "review", [Finding("oversize", "evasion", 0.5, f"{len(text)} chars")])
    clean, flags = normalize(text)
    findings = _apply(clean)
    if not any(f.rule == "override_i18n" for f in findings):
        for f in _apply(unfolded(text)):
            if f.rule == "override_i18n":  # folding turns real Russian into Latin look-alikes
                findings.append(f)
    seen = {f.rule for f in findings}
    hidden = False
    for label, variant in scan_variants(clean):
        for f in _apply(variant, f"{label}:"):
            if f.rule.split(":", 1)[1] not in seen:  # one finding per rule, from the most direct reading
                findings.append(f)
                hidden = True
    if not any(f.category == "instruction_override" for f in findings):
        sq = squash(clean)
        for rid, rx in _SQUASHED:
            if rx.search(sq):
                findings.append(Finding(f"squashed:{rid}", "instruction_override", 0.8, "spacing/punctuation removed"))
                hidden = True
                break
    if flags:
        findings.append(Finding("obfuscation", "evasion", 0.3, ",".join(flags)))
    if hidden:
        findings.append(Finding("hidden_payload", "evasion", 0.3, "encoded or disguised text"))
    miss = 1.0
    for f in findings:
        miss *= 1 - f.weight
    score = round(1 - miss, 3)
    action = "block" if score >= block_at else "review" if score >= review_at else "allow"
    return ScanResult(score, action, findings, flags)
