# SCORP: System CVE Observation & Remediation Protocol

Work with a team of Qwen AI agents to find out what known vulnerabilities your systems may have.

You describe the products you use (for example "a Ring camera, a Cisco RV340 router and Windows 11"). The agents look up real, published vulnerabilities (CVEs) for them in the US National Vulnerability Database (NVD), then give you a table of findings. If you want, they turn those findings into security requirements.

This is a class project for learning how to build multi-agent AI systems. It is not a security audit tool, so check anything important against [nvd.nist.gov](https://nvd.nist.gov).

## What it does

In the chat, type **`CVECheck`** or ask about a specific CVE such as `CVE-2024-20358`.

**A CVECheck**
1. **Intake.** The agents ask which systems you have, and label each one with an industry (IoT, Networking, Software, and so on). You can correct a label.
2. **Diagram.** They draw a block diagram of your systems. Each box is coloured by its industry and linked to your networking device. You can correct the diagram too.
3. **Search.** They look up CVEs for each system in NVD.
4. **Verify.** The model labels each CVE, and plain code filters out keyword collisions. For example, a RingCentral CVE does not belong to a Ring camera.
5. **Table.** You get a markdown table: system and version, CVE id, CWE, description, CVSS score and severity. It also lists what was excluded and why.
6. **Requirements (optional).** The agents ask whether you want the CVEs turned into "shall" requirements. If you say yes, they write them for each system, review them against INCOSE rules, rewrite the weak ones, and give you a report.

**A direct CVE lookup** (`CVE-2024-20358`) skips all of that and returns that one record.

## The agents

| Agent | Job |
|---|---|
| **Router** | The only agent you talk to. It decides who handles each message. |
| **Systems Expert** | Works out your systems, their industries and the diagram. |
| **Vulnerability Expert** | Searches NVD for CVEs and drafts requirements. The only agent allowed to use the CVE tool. |
| **Evaluator** | Reviews requirements against INCOSE rules. It reports problems and never rewrites. |
| **Writer** | Formats the final tables and reports. |

The agents are wired together with [LangGraph](https://langchain-ai.github.io/langgraph/). The chat pauses whenever it needs your reply, and your next message resumes the same run.

**The model checks nothing alone.** The model (Qwen2.5-3B-Instruct, a small model) writes text and labels things. Plain Python code then checks its work against the real data: CVE ids, scores, tables and quotes. If the model's answer is wrong, code fixes it or builds the result itself. A made-up CVE or CWE is rejected. The sidebar shows which agent is working, and **Show agent steps** lets you see what each agent passed on.

## Project layout

```text
AIClass_PythonCode/
├── CVE_TASK.py                  # The Streamlit chat app (start here)
├── colab_server.ipynb           # Colab notebook that runs the Qwen model
├── pyproject.toml               # Project dependencies (managed with uv)
├── .env.example                 # Copy to .env and fill in your values
├── .env                         # Your keys and Colab URL (not committed)
│
├── agents/                      # The agents (its own uv project)
│   ├── router/                  # Router agent and the LangGraph that connects them all
│   │   ├── agent.py             # Router agent, ChatSession, and the Colab model backend
│   │   ├── graph.py             # The main LangGraph that coordinates the agents
│   │   ├── requirements_graph.py  # The requirements loop (a LangGraph subgraph)
│   │   ├── graph_diagram.py     # Draws the agent diagram from the real graph
│   │   ├── status.py            # Sidebar panel: which agent is active, call counts
│   │   └── tracking.py          # Helpers shared by both graphs
│   ├── systems_expert/          # Finds your systems and draws the block diagram
│   │   ├── agent.py
│   │   └── diagram.py           # Diagram built by plain code, no model
│   ├── vulnerability_expert/    # Searches NVD for CVEs (the only agent that can)
│   │   ├── agent.py
│   │   └── requirements.py      # Writes requirements for the CVEs it found
│   ├── evaluator/               # Reviews requirements against INCOSE rules
│   │   └── agent.py
│   ├── writer/                  # Formats the final tables and reports
│   │   ├── agent.py
│   │   ├── requirements_report.py  # One section per component
│   │   └── tables.py            # Helpers for checking markdown tables
│   ├── shared/                  # Code used by several agents
│   │   ├── model_replies.py     # Helpers for structured model answers
│   │   ├── requirements_gate.py # Regex checks on requirements
│   │   └── skills.py            # Loads skills from the skills/ folder
│   └── pyproject.toml           # Agent dependencies and test settings
│
├── mcps/                        # MCP clients: how agents reach outside tools
│   ├── README.md                # See this for who may use which MCP
│   ├── TEMPLATE.md              # Copy this to add a new MCP
│   ├── pyproject.toml
│   └── mcps/
│       ├── __init__.py          # Passes the .env keys to the MCP server
│       └── cve.py               # The CVE tool (search and lookup)
│
├── skills/                      # Plain-text instructions that agents load
│   ├── README.md                # See this for the format and the full skill list
│   ├── vulnerability-intake/    # Works out which systems you have
│   ├── system-industry/         # Labels each system with an industry
│   ├── cve-verification/        # Filters CVEs that don't match your products
│   ├── vulnerability-table/     # Formats the findings table
│   ├── incose-requirements/     # Turns CVEs into "shall" requirements
│   ├── incose-evaluator/        # Reviews requirements
│   ├── requirements-table/      # Formats the requirements table
│   └── requirements-report/     # Writes each component's report section
│                                # (each skill folder holds one SKILL.md)
│
└── tests/                       # Automated tests (no network or model needed)
    └── try_requirements.py      # Not a test: runs the requirements loop without the chat
```

## Setup

You need [uv](https://docs.astral.sh/uv/) and a Google account for Colab.

**1. Start the model on Colab.** Open `colab_server.ipynb` in Google Colab and run it. It starts the model and prints a public URL and an API key.

**2. Create a `.env` file** in this folder by copying `.env.example` and filling in the values. Never commit `.env`. It is already in `.gitignore`.

```
COLAB_URL=https://your-address.trycloudflare.com
COLAB_KEY=the-key-the-notebook-printed
NVD_API_KEY=optional-but-raises-the-NVD-rate-limit
```

**3. Run the app.**

```
uv run --project agents streamlit run CVE_TASK.py
```

You can also paste the Colab URL and key into the app's sidebar instead of using `.env`. Refresh the page after you edit `.env`.

## Other commands

Try the requirements loop without the chat. `--demo` uses a fake model, so it only checks that the plumbing works.

```
uv run --project agents python tests/try_requirements.py --demo
uv run --project agents python tests/try_requirements.py
```

Run the tests:

```
uv run --project agents pytest
```

## Output Format

The report includes:
- A mermaid diagram of your systems
- CVE records per system
- Requirements to mitigate CVE records

**CVE findings table** (the end of a CVECheck). The row below is illustrative:

| # | System | CVE | CWE | Description | CVSS | Severity |
|---|---|---|---|---|---|---|
| 1 | Apache Log4j 2.14 | CVE-2021-44228 | CWE-502 | Remote code execution through crafted log messages | 10.0 | CRITICAL |

Under the table, code (not the model) lists the records that were excluded and why. It also lists "right vendor, different kind of product" records that were demoted, with the worst CVSS first. The CWE shows `N/A` when NVD lists none.

**Requirements report** (only if you say yes to the requirements offer). One section per system, each with:
- the CVEs it covers, with CVSS and severity
- how many times the Evaluator reviewed it
- a table with columns ID, Requirement, CVE, CWE, Verification and Quality check (**Pass** or **Needs review**)
- the issues the Evaluator found

Full results are also saved as JSON in `requirements_run/` when you use `tests/try_requirements.py`.

## Built with

Python, [uv](https://docs.astral.sh/uv/), [Streamlit](https://streamlit.io/), [LangGraph](https://langchain-ai.github.io/langgraph/), [FastMCP](https://gofastmcp.com/), [Qwen2.5-3B-Instruct](https://huggingface.co/Qwen/Qwen2.5-3B-Instruct) on Google Colab, and the [NVD](https://nvd.nist.gov) via [cve-mcp-server](https://github.com/mukul975/cve-mcp-server).

## Notes

- The model (Qwen2.5-3B) runs on Google Colab, because a laptop is too slow. The agents and the app run on your computer.
- Source availability and web search results may vary over time.
- Having an NVD key is not required, but highly recommended since the MCP makes multiple parallel calls that might get blocked unless a key is used.


## License

See [LICENSE](LICENSE).
