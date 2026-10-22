"""Canonicalise untrusted text so obfuscated injections look like plain ones."""

import base64
import binascii
import re
import unicodedata

_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿­‮"), None)
_HOMOGLYPHS = str.maketrans(
    {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ѕ": "s", "ԁ": "d"}
)
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def normalize(text: str) -> tuple[str, list[str]]:
    """Return (clean_text, obfuscation_flags)."""
    flags = []
    if any(ord(c) in _INVISIBLE for c in text):
        flags.append("invisible_chars")
    t = unicodedata.normalize("NFKC", text.translate(_INVISIBLE))
    folded = t.translate(_HOMOGLYPHS)
    if folded != t:
        flags.append("homoglyphs")
    return re.sub(r"\s+", " ", folded).strip(), flags


def decode_embedded(text: str) -> list[str]:
    """Decode base64 blobs that hide readable text."""
    found = []
    for m in _B64.finditer(text):
        blob = m.group(0)
        blob += "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(raw) >= 8 and raw.isprintable():
            found.append(raw)
    return found
