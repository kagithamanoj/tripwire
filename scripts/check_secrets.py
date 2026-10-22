"""P-07 evidence: fail if any secret-shaped string is present in the repo."""

import pathlib
import re
import sys

PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "api_key": re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "aws_secret": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    "aws_account_id_url": re.compile(r"\b\d{12}-[a-z0-9]{8}\.[a-z0-9-]+\.console\.aws"),
}
SKIP_DIRS = {".git", "__pycache__", "logs"}


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    hits, scanned = [], 0
    for p in root.rglob("*"):
        if not p.is_file() or SKIP_DIRS & set(p.relative_to(root).parts) or p.name.startswith("._"):
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        scanned += 1
        for name, rx in PATTERNS.items():
            if rx.search(text):
                hits.append((str(p.relative_to(root)), name))
    print(f"scanned {scanned} files, {len(hits)} findings")
    for h in hits:
        print("  FOUND", *h)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
