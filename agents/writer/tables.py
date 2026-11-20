"""Small helpers for reading a markdown table the model wrote (used by the Writer's checks)."""

import re

SEPARATOR_RE = re.compile(r"^\|[\s:\-|]+\|$")


def extract_table(text):
    """Keep only the table lines (drops code fences, intro text, etc.)."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("|")]
    return "\n".join(lines)


def split_cells(line):
    inner = line.strip().strip("|")
    return [c.replace("\\|", "|").strip() for c in re.split(r"(?<!\\)\|", inner)]
