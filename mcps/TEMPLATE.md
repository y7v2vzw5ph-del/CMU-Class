# Template for a new MCP

Copy the code below to `mcps/mcps/<name>.py` (for example `mcps/mcps/weather.py`), then work through the
checklist at the bottom. Replace everything in `<angle brackets>`.

## The module

```python
"""The <NAME> MCP. ONLY the <AGENT NAME> may use this module.

It starts <the server's name and link> as a child process and exposes just the calls we need, plus plain
functions that turn the server's text into clean data. The rule "only the <AGENT NAME> uses it" is checked
by tests/test_mcp_access.py (see the table in mcps/README.md).

<Why the server is started the way it is, if there is anything unusual (for example `uv tool run` to give
it its own environment).>
"""

import re

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from . import child_env  # the .env values (API keys) as a dict

SERVER_COMMAND = "<command>"        # for example "uv"
SERVER_ARGS = [<"arguments", "for", "the", "command">]


class <Name>Tool:
    """Use it like:  async with <Name>Tool() as tool:  text = await tool.<one_call>("<example input>")"""

    async def __aenter__(self):
        # The child process does not inherit our shell, so keys from .env are passed explicitly.
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

    async def <one_call>(self, <arguments>):
        """<What it does>. Returns the server's text."""
        return await self._call("<the server's tool name>", {"<argument>": <argument>})

    # Add one method per tool we actually use. Not more.


# ---- Turning the server's text into clean data -------------------------------
# Plain functions (no network), so they are easy to test with sample text.

SOMETHING_RE = re.compile(r"<a pattern for a line of the server's output>", re.MULTILINE)


def parse_<thing>(text):
    """<The shape of the text> -> <the shape of the data>, or None if the text is not recognised."""
    match = SOMETHING_RE.search(text)
    if not match:
        return None
    return {"<field>": match.group(1)}
```

## The test (start from this)

Put it in `tests/test_<name>_mcp.py`. Use real sample text copied from the server, so the test notices when
the server changes its output.

```python
from mcps.<name> import parse_<thing>

SAMPLE = """<paste a real answer from the server here>"""


def test_parse_<thing>_reads_the_sample():
    assert parse_<thing>(SAMPLE) == {"<field>": "<expected value>"}


def test_parse_<thing>_of_unrecognised_text_is_none():
    assert parse_<thing>("something else entirely") is None
```

## Checklist

- [ ] The module is `mcps/mcps/<name>.py` and imports `child_env` from `.` (not a path of its own).
- [ ] **Who may use it?** Add the row to the table in `mcps/README.md` **and** to `MCP_USERS` in
      `tests/test_mcp_access.py`, for example `"<name>": ("agents/<agent_folder>",)`.
- [ ] Only that agent imports it (the access test fails if anyone else does).
- [ ] The server's library clashes with ours? Start it with `uv tool run --with ...`.
- [ ] Parsing functions have tests with sample text.
- [ ] Keys come from `.env`, never from the code. Tell the user which keys to put in `.env`.
- [ ] `uv run --project agents pytest` passes.
