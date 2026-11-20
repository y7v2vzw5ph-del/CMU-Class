"""The CVE MCP. ONLY the Vulnerability Expert may use this module.

It starts the cve-mcp-server (github.com/mukul975/cve-mcp-server) as a child
process and exposes just the two calls we need, plus plain functions that turn the
server's text into clean data. The rule "only the Vulnerability Expert uses it" is
checked by tests/test_mcp_access.py (see the table in mcps/README.md).

Why `uv tool run`: cve-mcp-server needs the older MCP 1.x library, but fastmcp
(used by this project) needs MCP 2.x. They can't share one environment, so
`uv tool run` runs the server in its own separate, cached environment with
"mcp<2". GitHub's zip download is used because git isn't installed here.
"""

import re

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from . import child_env

SERVER_COMMAND = "uv"
SERVER_ARGS = [
    "tool", "run",
    "--from", "https://github.com/mukul975/cve-mcp-server/archive/refs/heads/main.zip",
    "--with", "mcp<2",
    "cve-mcp",
]


class CveTool:
    """Use it like:  async with CveTool() as tool:  text = await tool.lookup("CVE-2023-23397")"""

    async def __aenter__(self):
        # Optional keys (like NVD_API_KEY) live in the project's .env file. The child process
        # doesn't inherit our shell, so pass them explicitly.
        self._client = Client(
            StdioTransport(command=SERVER_COMMAND, args=SERVER_ARGS, env=child_env())
        )
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_info):
        return await self._client.__aexit__(*exc_info)

    async def _call(self, name, arguments):
        result = await self._client.call_tool(name, arguments)
        return "\n".join(c.text for c in result.content if hasattr(c, "text"))

    async def search(self, query, limit=10):
        """Keyword search. Returns text with one line per CVE (description cut short)."""
        return await self._call("search_cves", {"query": query, "limit": limit})

    async def lookup(self, cve_id):
        """Full details for one CVE id, as text."""
        return await self._call("lookup_cve", {"cve_id": cve_id})


# ---- Turning the tool's text into clean data ---------------------------------
# These are plain functions (no network), so they are easy to test.

SEARCH_LINE_RE = re.compile(r"^\s*(CVE-\d{4}-\d{4,})\s+(.*)$", re.MULTILINE)
SEARCH_SCORE_RE = re.compile(r"Score:\s*([\d.]+|N/A)(?:\s*\((\w+)\))?\s*(.*)$")
# Old CVEs only have a CVSS v2 score, so the line can be "Score:     10.0 " with NO
# severity word. Use [ \t] (not \s) so we never run into the next line.
LOOKUP_SCORE_RE = re.compile(r"^Score:[ \t]+([\d.]+)(?:[ \t]+(\w+))?[ \t]*$", re.MULTILINE)
LOOKUP_VECTOR_RE = re.compile(r"^Vector:[ \t]+(\S+)", re.MULTILINE)
# "Weaknesses: CWE-502, CWE-400" (only present when NVD lists weaknesses). NVD also uses
# placeholders like NVD-CWE-noinfo and NVD-CWE-Other; they have no number, so CWE_ID_RE skips them.
LOOKUP_WEAKNESSES_RE = re.compile(r"^Weaknesses:[ \t]+(.+)$", re.MULTILINE)
CWE_ID_RE = re.compile(r"\bCWE-\d+\b")
# Descriptions can span several paragraphs, and Description is the last section.
LOOKUP_DESCRIPTION_RE = re.compile(r"^Description:\s*\n(.*)\Z", re.MULTILINE | re.DOTALL)


def _to_float(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None  # e.g. "N/A"


def parse_search_results(text):
    """'CVE-2023-31122  Score: 7.5 (HIGH)  Out-of-bounds...' lines -> list of dicts.

    The description here is shortened by the tool (ends with '...'); use
    parse_lookup() on lookup_cve's output for the full text.
    """
    items = []
    for match in SEARCH_LINE_RE.finditer(text):
        score = SEARCH_SCORE_RE.search(match.group(2))
        items.append(
            {
                "cve_id": match.group(1),
                "cvss": _to_float(score.group(1)) if score else None,
                "severity": (score.group(2) or "").upper() or None if score else None,
                "description": score.group(3).strip() if score else match.group(2).strip(),
            }
        )
    return items


def _v2_severity(score):
    """NVD's official CVSS v2 bands. Only used when the tool gives no severity word."""
    if score is None:
        return None
    return "LOW" if score < 4.0 else "MEDIUM" if score < 7.0 else "HIGH"


def parse_cwes(text):
    """The CWE ids in a lookup_cve text, in order, without repeats. [] if NVD lists none."""
    line = LOOKUP_WEAKNESSES_RE.search(text)
    return list(dict.fromkeys(CWE_ID_RE.findall(line.group(1)))) if line else []


def parse_lookup(text):
    """lookup_cve text -> {"cvss", "severity", "description", "cwes"}, or None if unrecognized."""
    score = LOOKUP_SCORE_RE.search(text)
    description = LOOKUP_DESCRIPTION_RE.search(text)
    if not score and not description:
        return None
    cvss = _to_float(score.group(1)) if score else None
    severity = score.group(2).upper() if score and score.group(2) else None
    if severity is None:
        # No severity word means an old CVSS v2 score (v3 vectors start with "CVSS:3").
        vector = LOOKUP_VECTOR_RE.search(text)
        if vector and not vector.group(1).startswith("CVSS:3"):
            severity = _v2_severity(cvss)
    return {
        "cvss": cvss,
        "severity": severity,
        # Collapse line breaks and blank lines into single spaces (keeps tables on one line).
        "description": " ".join(description.group(1).split()) if description else None,
        "cwes": parse_cwes(text),  # e.g. ["CWE-787"]; [] when NVD lists none
    }
