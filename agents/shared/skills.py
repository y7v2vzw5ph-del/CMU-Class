"""Load skills from the top-level skills/ folder.

A skill is skills/<name>/SKILL.md. It starts with a small header between '---'
lines:
    name: ...
    description: ...
    triggers: word one, word two     (comma-separated)
Everything after the header is the instructions we give the model.

Any agent can load the skills it needs by name with get_skill().
"""

from pathlib import Path

# This file is agents/shared/skills.py, so parents[2] is the AIClass_PythonCode
# folder. If you move the skills folder, update this path.
SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"


def load_skills():
    """Read every skills/<name>/SKILL.md into a list of dicts."""
    skills = []
    for path in sorted(SKILLS_DIR.glob("*/SKILL.md")):
        text = path.read_text(encoding="utf-8")
        parts = text.split("---", 2)  # ['', header, body]
        if len(parts) < 3:
            continue  # no header -> not a valid skill
        meta = {}
        for line in parts[1].strip().splitlines():
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
        triggers = [t.strip().lower() for t in meta.get("triggers", "").split(",")]
        skills.append(
            {
                "name": meta.get("name", path.parent.name),
                "triggers": [t for t in triggers if t],
                "instructions": parts[2].strip(),
                "meta": meta,  # every header line, e.g. meta["question_scope"]
            }
        )
    return skills


def get_skill(name):
    """Return one skill by name. Raises a clear error if it doesn't exist."""
    for skill in load_skills():
        if skill["name"] == name:
            return skill
    raise FileNotFoundError(f"No skill named '{name}' in {SKILLS_DIR}")


def is_triggered(skill, texts):
    """True if any of the skill's trigger words appears in any of the texts.

    Pass in the whole chat's user messages (not just the newest one) so a skill
    stays on while the user answers its follow-up questions with short replies.
    """
    text = " ".join(texts).lower()
    return any(t in text for t in skill["triggers"])
