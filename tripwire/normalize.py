"""Canonicalise untrusted text so obfuscated injections look like plain ones.

`normalize` makes one clean reading; `scan_variants` produces the extra readings an
attacker may be relying on (url/html/hex/base64/rot13/leetspeak).
"""

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse

# Zero-width, bidi controls, variation selectors, soft hyphen.
_INVISIBLE_CHARS = "​‌‍‎‏⁠﻿­‪‫‬‭‮⁦⁧⁨⁩"
_INVISIBLE = dict.fromkeys(map(ord, _INVISIBLE_CHARS), None)
_INVISIBLE.update(dict.fromkeys(range(0xFE00, 0xFE10), None))
_TAG_CHARS = re.compile("[\U000E0020-\U000E007E]")
_TAG_OTHER = re.compile("[\U000E0000-\U000E001F\U000E007F]")
_HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ѕ": "s", "ԁ": "d",
    "у": "y", "к": "k", "т": "t", "н": "h", "м": "m", "в": "b", "ј": "j",
    # Greek
    "α": "a", "ε": "e", "ι": "i", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "κ": "k", "χ": "x",
    "ı": "i",
})
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
_LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalize(text: str) -> tuple[str, list[str]]:
    """Return (clean_text, obfuscation_flags)."""
    flags = []
    if _TAG_CHARS.search(text):
        flags.append("tag_chars")  # invisible ASCII smuggling: decode it so it can be read and scanned
        text = _TAG_CHARS.sub(lambda m: chr(ord(m.group()) - 0xE0000), text)
    text = _TAG_OTHER.sub("", text)
    if any(ord(c) in _INVISIBLE for c in text):
        flags.append("invisible_chars")
    t = unicodedata.normalize("NFKC", text.translate(_INVISIBLE))
    folded = t.translate(_HOMOGLYPHS)
    if folded != t:
        flags.append("homoglyphs")
    return re.sub(r"\s+", " ", folded).strip(), flags


def unfolded(text: str) -> str:
    """Like normalize() but without homoglyph folding, so genuine non-Latin text stays readable."""
    text = _TAG_CHARS.sub(lambda m: chr(ord(m.group()) - 0xE0000), text)
    text = _TAG_OTHER.sub("", text)
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text.translate(_INVISIBLE))).strip()


def _printable(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if len(s) >= 8 and all(c.isprintable() or c in "\n\t" for c in s) else None


def decode_embedded(text: str, depth: int = 3) -> list[str]:
    """Decode base64 / hex blobs that hide readable text (nested up to `depth`)."""
    found = []
    for m in _B64.finditer(text):
        blob = m.group(0)
        blob += "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        s = _printable(raw)
        if s:
            found.append(s)
    for m in _HEX.finditer(text):
        s = _printable(bytes.fromhex(m.group(0)))
        if s:
            found.append(s)
    if depth > 1:
        for s in list(found):
            found += decode_embedded(s, depth - 1)
    return found


def squash(text: str) -> str:
    """Letters and digits only, lower-cased: defeats spacing, hyphens, dots and zero-width tricks."""
    return re.sub(r"[^0-9a-z\u0080-\U0010ffff]", "", text.lower())


def scan_variants(clean: str) -> list[tuple[str, str]]:
    """Alternative readings of already-normalised text, as (label, text)."""
    out = []
    if "%" in clean:
        out.append(("urldecoded", urllib.parse.unquote(clean)))
    if "&" in clean:
        out.append(("htmldecoded", html.unescape(clean)))
    out.append(("rot13", codecs.encode(clean, "rot13")))
    leet = clean.translate(_LEET)
    if leet != clean:
        out.append(("leetspeak", leet))
    for blob in decode_embedded(clean):
        inner, _ = normalize(blob)
        out.append(("decoded", inner))
        out.extend((f"decoded+{lbl}", t) for lbl, t in scan_variants_light(inner))
    return out


def scan_variants_light(clean: str) -> list[tuple[str, str]]:
    """Cheap second-layer readings for text found inside an encoded blob."""
    out = [("rot13", codecs.encode(clean, "rot13"))]
    if "%" in clean:
        out.append(("urldecoded", urllib.parse.unquote(clean)))
    return out
