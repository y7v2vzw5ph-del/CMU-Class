"""The rule for the MCPs: each MCP in mcps/mcps/ may be imported only by the agent(s) named for it.

mcps/README.md has the table; MCP_USERS below is the same table in code. When you add an MCP, add a row
here (the test below fails until you do), so every MCP has an owner.

Not checked: tests/ (they may import any MCP to test its parsing functions) and mcps/ itself.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# MCP name -> the folders (relative to the project root) whose files may import it.
MCP_USERS = {
    "cve": ("agents/vulnerability_expert",),
}

SKIPPED_FOLDERS = {".venv", "venv", "__pycache__", ".pytest_cache", "tests", "mcps"}


def mcps_imported_by(path):
    """The MCP names a Python file imports. 'from mcps.cve import X', 'import mcps.cve' and
    'from mcps import cve' all give {"cve"}."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "mcps" and len(parts) > 1:
                    names.add(parts[1])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            parts = node.module.split(".")
            if parts[0] == "mcps":
                names.update([parts[1]] if len(parts) > 1 else [alias.name for alias in node.names])
    return names


def violations(root, rules):
    """One sentence for every file under `root` that imports an MCP it may not use."""
    found = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if SKIPPED_FOLDERS & set(relative.parts[:-1]):
            continue
        for name in sorted(mcps_imported_by(path)):
            allowed = rules.get(name, ())
            if not any(relative.as_posix().startswith(folder.rstrip("/") + "/") for folder in allowed):
                who = ", ".join(allowed) or "nobody"
                found.append(f"{relative.as_posix()} imports the '{name}' MCP, which only {who} may use")
    return found


# ---- The project follows the rule ----------------------------------------------------

def test_only_the_named_agent_imports_each_mcp():
    assert violations(ROOT, MCP_USERS) == []


def test_only_the_vulnerability_expert_uses_the_cve_mcp():
    users = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.py")
             if not SKIPPED_FOLDERS & set(p.relative_to(ROOT).parts[:-1]) and "cve" in mcps_imported_by(p)]
    assert users and all(u.startswith("agents/vulnerability_expert/") for u in users)  # it IS used, and only there


def test_every_mcp_module_has_an_owner_and_every_owner_has_a_module():
    modules = {p.stem for p in (ROOT / "mcps" / "mcps").glob("*.py") if p.stem != "__init__"}
    assert modules == set(MCP_USERS), "add (or remove) the MCP's row in MCP_USERS, and in mcps/README.md"
    for folders in MCP_USERS.values():
        assert all((ROOT / folder).is_dir() for folder in folders)  # an owner that exists


# ---- The check itself catches a breach (so a passing result means something) ----------

def write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_the_check_catches_every_way_of_importing_an_mcp_from_the_wrong_place(tmp_path):
    rules = {"cve": ("agents/vulnerability_expert",)}
    write(tmp_path, "agents/vulnerability_expert/agent.py", "from mcps.cve import CveTool\n")  # allowed
    write(tmp_path, "agents/vulnerability_expert/deeper/x.py", "import mcps.cve\n")  # allowed: inside the folder
    write(tmp_path, "tests/test_x.py", "from mcps.cve import parse_lookup\n")  # tests may import
    write(tmp_path, "agents/writer/agent.py", "from mcps.cve import CveTool\n")
    write(tmp_path, "agents/systems_expert/agent.py", "import mcps.cve as tool\n")
    write(tmp_path, "agents/evaluator/agent.py", "from mcps import cve\n")
    write(tmp_path, "agents/router/agent.py", "from mcps.weather import WeatherTool\n")  # an MCP nobody owns
    write(tmp_path, "agents/vulnerability_expert_but_not_really/a.py", "from mcps.cve import CveTool\n")  # similar name
    write(tmp_path, "CVE_TASK.py", "from mcps.cve import CveTool\n")  # a root-level script is not an agent

    found = violations(tmp_path, rules)
    offenders = sorted(line.split(" ")[0] for line in found)
    assert offenders == [
        "CVE_TASK.py",
        "agents/evaluator/agent.py",
        "agents/router/agent.py",
        "agents/systems_expert/agent.py",
        "agents/vulnerability_expert_but_not_really/a.py",
        "agents/writer/agent.py",
    ]
    assert any("'weather' MCP, which only nobody may use" in line for line in found)


def test_environments_and_the_mcps_folder_itself_are_not_checked(tmp_path):
    write(tmp_path, "agents/.venv/lib/x.py", "from mcps.cve import CveTool\n")
    write(tmp_path, "mcps/mcps/other.py", "from mcps.cve import CveTool\n")
    assert violations(tmp_path, {"cve": ("agents/vulnerability_expert",)}) == []
