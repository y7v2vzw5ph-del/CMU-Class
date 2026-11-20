"""Shared MCP clients: one module per MCP (for example mcps/cve.py).

Read the README.md in the folder above this one before adding or using an MCP. It explains the layout
and the rule about WHICH agent may use each MCP.

What lives here, in this __init__.py, is only what every MCP needs: where the project's .env file is.
"""

from pathlib import Path

from dotenv import dotenv_values

# This file is mcps/mcps/__init__.py: parents[0] is mcps/mcps, parents[1] is the mcps folder and
# parents[2] is the project root (AIClass_PythonCode), where the .env file lives.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"


def child_env():
    """The values in the project's .env file (like NVD_API_KEY) as a dict.

    An MCP server started as a child process does not inherit our shell's environment, so its
    wrapper passes these along explicitly. Empty values are left out. Never commit the .env file.
    """
    return {key: value.strip() for key, value in dotenv_values(ENV_FILE).items() if value}
