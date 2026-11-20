# MCPs

This folder holds the **MCP clients** that agents use to reach outside tools. It sits next to
`agents/` so any agent *could* use an MCP, but each MCP names **which agent(s) may use it**
(see the table below). A test enforces it.

## What is an MCP here?

An MCP (Model Context Protocol) server is a small program that offers tools, like "search CVEs".
Our code starts the server and calls its tools through an **MCP client**. The client is what lives in
this folder: a short Python module that

1. starts the server (usually as a child process),
2. exposes just the calls we need (`search`, `lookup`, ...), and
3. has **plain functions that turn the server's text into clean data** (no network, so easy to test).

The server itself is usually somebody else's program (we do not copy it into the project).

## Layout

```
mcps/                      <- this folder (a small Python package of its own)
├── README.md              <- you are here
├── TEMPLATE.md            <- copy this to make a new MCP
├── pyproject.toml         <- makes `mcps` installable; agents/pyproject.toml depends on it by path
└── mcps/                  <- the importable package:   from mcps.cve import CveTool
    ├── __init__.py        <- what every MCP needs: where the .env file is (child_env())
    └── cve.py             <- the CVE MCP
```

## The MCPs we have

| MCP | Module | Server | Tools we use | Who may use it |
|---|---|---|---|---|
| **cve** | `mcps/mcps/cve.py` | [cve-mcp-server](https://github.com/mukul975/cve-mcp-server), run by `uv tool run` in its own cached environment (it needs the old MCP 1.x library, which cannot share an environment with `fastmcp`) | `search_cves` (a list of CVEs with a score and a shortened description), `lookup_cve` (one CVE in full: severity, weaknesses/CWE, description) | **Vulnerability Expert only** (`agents/vulnerability_expert/`) |

Optional keys such as `NVD_API_KEY` go in the project's `.env` file. `child_env()` passes them to the server.
Never commit `.env`.

## The rule: who may use an MCP

Every MCP is given to **one agent** (or a short list). No other agent may import it. This keeps each agent
limited to its own tools: the Writer can never search CVEs, the Router can never call the CVE tool, and so on.

- The table above is the rule in words. The same table is in code as `MCP_USERS` in
  `tests/test_mcp_access.py`.
- That test reads every Python file in the project and **fails if a file outside the allowed folder imports
  the MCP**. It also fails if an MCP module has no row in `MCP_USERS`, so you cannot add an MCP without
  deciding who may use it.
- Tests (`tests/`) may import any MCP, to test its parsing functions.

## Using an MCP from an agent

```python
from mcps.cve import CveTool, parse_lookup

async with CveTool() as tool:
    text = await tool.lookup("CVE-2023-23397")
details = parse_lookup(text)       # {"cvss": ..., "severity": ..., "description": ..., "cwes": [...]}
```

`agents/pyproject.toml` lists `mcps` as a dependency with a path (`../mcps`), so
`uv run --project agents ...` installs it from this folder. Edits here show up immediately.

## Adding a new MCP

1. Read `TEMPLATE.md` and copy it to `mcps/mcps/<name>.py`.
2. Fill in the server command, the tools you need, and the parsing functions.
3. **Decide who may use it** and add a row to `MCP_USERS` in `tests/test_mcp_access.py`
   and to the table above.
4. Write tests for the parsing functions with sample text (no network), like the CVE ones in
   `tests/test_vulnerability_expert.py`.
5. Run the tests: `uv run --project agents pytest`.

If the new MCP's server needs a library that clashes with the project's (like the CVE one does), run it
with `uv tool run --with ...` so it gets its own environment.

## Rules of thumb

- **One module per MCP.** Keep the client class and its parsing functions together.
- **Parsing functions are plain functions**: text in, data out, no network. They are the part most
  likely to break when the server changes its output, so they are the part to test.
- **Expose only what we use.** If we only call two tools, the class has two methods.
- **No secrets in code.** Keys come from `.env` through `child_env()`.
