#!/usr/bin/env python3
"""
Validate markdown docs for local link/file drift and known stale commands.
"""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DOC_GLOBS = ["README.md", "docs/**/*.md", "ai-analyst/README.md"]

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def iter_markdown_files():
    for pattern in DOC_GLOBS:
        for path in ROOT.glob(pattern):
            if path.is_file():
                yield path


def is_local_link(target: str) -> bool:
    if not target or target.startswith("#"):
        return False
    if target.startswith(("http://", "https://", "mailto:")):
        return False
    return True


def normalize_target(base_file: Path, target: str) -> Path:
    clean = target.split("#", 1)[0].split("?", 1)[0]
    return (base_file.parent / clean).resolve()


def main() -> int:
    errors = []
    stale_patterns = [
        ("terraform output wazuh_public_ip", "use `terraform output wazuh_server_public_ip`"),
    ]

    for md_file in iter_markdown_files():
        text = md_file.read_text(encoding="utf-8")

        for stale, fix in stale_patterns:
            if stale in text:
                errors.append(f"{md_file}: stale command `{stale}` found; {fix}")

        for match in LINK_RE.finditer(text):
            target = match.group(1).strip()
            if not is_local_link(target):
                continue
            resolved = normalize_target(md_file, target)
            if not resolved.exists():
                errors.append(f"{md_file}: broken local link `{target}`")

    if errors:
        print("Documentation validation failed:")
        for err in errors:
            print(f"- {err}")
        return 1

    print("Documentation validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
