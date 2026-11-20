# Skills

All skills live in this folder, next to `agents/` and `mcps/`. A skill is a
folder with one `SKILL.md` file. Agents load the skills they use by name with
`get_skill()` from `agents/shared/skills.py`. If you move this folder, update
`SKILLS_DIR` in that file.

```
skills/
└── my-skill/
    └── SKILL.md
```

## SKILL.md format

```
---
name: my-skill
description: One line saying what the skill is for.
triggers: word one, word two, another phrase
---

Instructions for the model, written as short, direct rules.
```

- **triggers** are comma-separated. `is_triggered()` returns true when ANY
  trigger text appears in ANY of the user's messages in the current chat
  (lowercase, substring match). So `vulnerab` matches vulnerability,
  vulnerabilities and vulnerable. Checking the whole chat means it stays on for
  short answers like "one" or "Windows 11". The Router uses triggers to decide
  which agent to hand a question to.
- The text under the `---` is the instructions the agent that owns the skill
  adds to its prompt.
- Keep instructions short and explicit. The model is a small 3B model.

## Current skills

| Skill | Used by | What it does |
|---|---|---|
| **vulnerability-intake** | Systems Expert | Works out which systems the user has. How they are connected is not asked: the diagram links every system automatically. A single system gets a text-only confirmation with no diagram. One or many is worked out from how many systems are named, so it is never asked. The Router asks the user what the SE says is missing. Asking for a specific CVE ID (e.g. "CVE-2024-20358") does not trigger it. Besides the trigger word, the Router can also *offer* it: if the model thinks a message is a security question about a product, the Router asks "Want me to run a CVECheck?" and only starts after a "yes" (see `router/graph.py`). |

| **vulnerability-table** | Writer | Formats the Vulnerability Expert's findings as a markdown table: row number, system and version, CVE id, CWE, CVE text, CVSS score, severity. The CWE comes from the `Weaknesses:` line of the CVE tool's `lookup_cve` text (read by `parse_lookup` in `mcps/mcps/cve.py` and carried on each row as `cwes`); it shows `N/A` when NVD lists none, and code checks the model's CWE cell like the CVE id, so a made-up CWE is rejected. It's loaded by name, so it has no trigger words. The Writer checks the model's table against the real data and falls back to a code-built table if it's wrong. Under the table, plain code (not the model) lists the excluded records with their reasons, and a "right vendor, different kind of product" list of the demoted records (id, system, CVSS, one-line reason, worst CVSS first, at most 15). |

| **cve-verification** | Systems Expert | After the Vulnerability Expert finds CVEs by keyword, the model only LABELS each record: `product_family` (same / related / different / unknown) and `cve_industry` (one category from the system-industry list, or unknown). Python then decides, using the industry the user confirmed: family **different** -> excluded (a keyword collision like RingCentral for a Ring camera); the CVE's industry clearly differs from the confirmed one -> **demoted** (id, CVSS and a one-line reason written by code); everything else, including every "unknown" and "Other", -> kept. Loaded by name, no trigger words. If the model's answer can't be read, the CVE is kept and marked "could not check" (hiding a real vulnerability is worse than showing one extra). A direct CVE-id lookup skips the check. |

| **system-industry** | Systems Expert | After the intake and before the diagram, labels each system with ONE industry category from the skill's `categories` line (IoT, Wearables, Fintech, Software, Hardware, Networking, Other; operating systems count as Software). The labels are shown in the confirmation message so the user can correct them ("the Ring camera is IoT"), and the confirmed labels are saved in `info["industry"]` for the CVE check later. An answer outside the list becomes "Other". Loaded by name, no trigger words. |

| **incose-requirements** | Vulnerability Expert (`agents/vulnerability_expert/requirements.py`) | Only after the user says yes to "Would you like me to turn these CVE records into requirements?", which is asked under the vulnerability table of a normal CVECheck. Loaded by name, no trigger words. Turns ONE CVE at a time into INCOSE-style "shall" requirements (JSON: id, component, statement, rationale, sources, verification, assumptions, gate_status), and rewrites them when the Evaluator finds problems. A component is one of the user's systems. Code, not the model, sets the ids, the component and the CVE each requirement traces to. After each CVE, plain code runs `check_all()` from `agents/shared/requirements_gate.py` (regex checks: "shall", banned words, missing fields, duplicate ids, CVE id format); if it finds errors the model sees them and rewrites only that CVE, up to 3 tries, then the best attempt is kept and marked `failed_gate`. |

| **incose-evaluator** | Evaluator (`agents/evaluator/agent.py`, `review_component()`) | Reviews the requirements of ONE component: the model quotes each requirement, checks it against the INCOSE rules, and gives a pass or revise verdict with a suggested rewrite, then looks for duplicates and contradictions inside the component. Code checks the model's answer (the quote really is in the requirement, every requirement was reviewed, a revise has evidence) and works out CVE coverage and duplicate ids itself. The result is `pass`, `revise` or `incomplete` (a review the model never produced is never counted as a pass). It reports and never rewrites. There is no cross-component check. Loaded by name, no trigger words. |


| **requirements-table** | Writer (`agents/writer/requirements_report.py`) | Only in a requirements report. Formats ONE component's requirements as a markdown table: ID, Requirement, CVE, CWE, Verification, Quality check (Pass or Needs review). The CWEs are set by code from the CVE record (never by the model), and show `N/A` when NVD lists none. Loaded by name, no trigger words. Like `vulnerability-table`, the model only formats: code checks the ids, CVEs and statuses and the start of each text against the real data, gives the model one chance to fix the listed problems, and otherwise builds the table itself. |

| **requirements-report** | Writer (`agents/writer/requirements_report.py`) | Only in a requirements report. Writes ONE component's section around the table: a heading with just the system's name (no Pass or Needs review mark beside it: each requirement's own Quality check is in its table row), the CVEs it covers (with CVSS and severity), how many times the Evaluator reviewed it, the line `[TABLE]` (code puts the verified table there), and the issues the Evaluator found. Loaded by name, no trigger words. Code checks the exact heading (only the name), every CVE and issue, that no table or invented CVE/requirement id was written, then one retry, then a code-built section. If any part falls back to code, the report says so. |

**The pauses and the requirements loop** (`router/graph.py`, `router/requirements_graph.py`, `router/agent.py`). Whenever the team needs your reply (which systems? is the diagram right? want a CVECheck? want requirements?) the graph PAUSES at the `ask_user` step (LangGraph `interrupt()`), and your next message RESUMES the same run. A checkpointer kept in a `ChatSession` holds the run's state in between (the systems, the diagram, the CVE results), so nothing has to be saved in the chat history. A reply that does not answer the question (a CVE id, a new question) ends that run and starts a fresh one, so nothing from the old run can leak into it. A normal CVECheck ends with the vulnerability table and the question "Would you like me to turn these CVE records into requirements?", and waits. **yes** runs the requirements loop on those results, one component (system) at a time: the Vulnerability Expert writes, the Evaluator reviews, and if the Evaluator found mistakes the Vulnerability Expert can fix and it has been reviewed fewer than 2 times, the Vulnerability Expert rewrites only the CVEs with problems and the Evaluator reviews again. After a clean review, or after the 2nd review, the Evaluator hands the component to the Writer with whatever mistakes remain. The loop is a LangGraph **subgraph** (`router/requirements_graph.py`), used by the chat as one step and by `try_requirements.py` on its own, so it is written once. The Writer then shows the requirements per component as **Pass** or **Needs review** (with the `requirements-table` and `requirements-report` skills), with its CVEs, each requirement's CVE, and the Evaluator's issues. **no** ends the check. A direct CVE-id lookup, or a check that found no CVEs, gets no offer. Try the loop without the chat: `uv run --project agents python tests/try_requirements.py --demo`.

**Not a skill: the block diagram.** There used to be a `block-diagram` skill, but the diagram is now built by plain code in `agents/systems_expert/diagram.py`, with no model. Every system is linked by a solid line to the networking device (the system labelled Networking by system-industry); with no networking device nothing is linked, and there is no separate "Network" box. Each box is coloured by its industry. The user changes what is connected by correcting an industry ("the Cisco RV340 is Networking").
