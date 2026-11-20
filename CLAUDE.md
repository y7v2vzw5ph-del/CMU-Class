# Project notes for Claude

SCORP: a multi-agent CVE checker. See README.md for what it does and how it is laid out.

Environment:
- Uses uv for Python package and environment management. Use uv commands (uv add, uv run, uv sync) instead of pip or python -m venv.
- Run the app: `uv run --project agents streamlit run CVE_TASK.py`
- Run the tests: `uv run --project agents pytest`
- Never commit `.env` (it holds API keys).
