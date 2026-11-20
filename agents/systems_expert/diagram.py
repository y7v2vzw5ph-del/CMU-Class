"""Block diagram helpers for the Systems Expert (no model, no network).

The diagram is Mermaid text built entirely by code, so a name can never be
dropped, renamed or invented.

Connections are automatic, from one rule:
- If there is a networking device in the list (a system whose industry is
  "Networking", for example a router), every other system is joined to it by a
  solid line.
- If there is NO networking device, nothing is connected: the systems are drawn
  as separate boxes.
There is no separate "Network" box. (With several networking devices, the extra
ones are joined to the first, so they stay one group.)

Each system's box is coloured by its industry (IoT, Software, ...), so the
user can check the labels at a glance. See INDUSTRY_STYLES.

Mermaid syntax used (all from the Mermaid docs):
    S1 --- S2                            a solid line
    classDef iot fill:#...,stroke:#...   a colour style
    class S1,S2 iot                      give boxes that style
"""

import re

HEADER = "graph LR"

# One style per industry. The keys are the category names in lower case (they
# match the `categories` line of the system-industry skill). `emoji` is the
# square used in the colour key under the diagram; it matches the fill colour.
INDUSTRY_STYLES = {
    "iot": {"fill": "#A5D6A7", "stroke": "#2E7D32", "emoji": "🟩"},
    "wearables": {"fill": "#CE93D8", "stroke": "#6A1B9A", "emoji": "🟪"},
    "fintech": {"fill": "#FFF59D", "stroke": "#F9A825", "emoji": "🟨"},
    "software": {"fill": "#90CAF9", "stroke": "#1565C0", "emoji": "🟦"},
    "hardware": {"fill": "#FFCC80", "stroke": "#E65100", "emoji": "🟧"},
    "networking": {"fill": "#EF9A9A", "stroke": "#C62828", "emoji": "🟥"},
    "other": {"fill": "#E0E0E0", "stroke": "#616161", "emoji": "⬜"},
}
FALLBACK_STYLE = "other"  # an industry with no style of its own (or no label yet)
NETWORKING = "networking"  # the industry that counts as a networking device


def clean_label(name):
    """Quotes would break the Mermaid text."""
    return name.replace('"', "'")


def style_key(industry_name):
    """'IoT' -> 'iot'. Anything without a style of its own uses the 'other' style."""
    key = re.sub(r"[^a-z0-9]", "", (industry_name or "").lower())
    return key if key in INDUSTRY_STYLES else FALLBACK_STYLE


def auto_edges(systems, industry):
    """Which systems are joined, as (i, j) pairs of system indexes (0 = the first system).

    Every system is joined to the first networking device. With no networking
    device there are no links at all.
    """
    industry = industry or {}
    devices = [i for i, s in enumerate(systems) if style_key(industry.get(s)) == NETWORKING]
    if not devices:
        return []
    hub = devices[0]
    return [(i, hub) for i in range(len(systems)) if i != hub]


def build_diagram(systems, industry=None):
    """Mermaid text for the systems, their automatic links and their industry colours.

    industry: {system name: category}. Systems with no label get the grey 'other' style.
    """
    industry = industry or {}
    lines = [HEADER]
    for i, name in enumerate(systems, start=1):
        lines.append(f'    S{i}["{clean_label(name)}"]')
    for i, j in auto_edges(systems, industry):
        lines.append(f"    S{i + 1} --- S{j + 1}")

    by_style = {}
    for i, name in enumerate(systems, start=1):
        by_style.setdefault(style_key(industry.get(name)), []).append(f"S{i}")
    for key, ids in by_style.items():  # only the styles that are used
        style = INDUSTRY_STYLES[key]
        lines.append(f"    classDef {key} fill:{style['fill']},stroke:{style['stroke']},color:#000")
        lines.append(f"    class {','.join(ids)} {key}")
    return "\n".join(lines)


def colour_key(systems, industry):
    """One line explaining the colours, listing only the industries in use.

    '🟦 Software · 🟩 IoT'. Returns '' if there is nothing to explain.
    """
    industry = industry or {}
    seen = {}
    for name in systems:
        label = industry.get(name)
        if label:
            seen.setdefault(label, INDUSTRY_STYLES[style_key(label)]["emoji"])
    return " · ".join(f"{emoji} {label}" for label, emoji in seen.items())
