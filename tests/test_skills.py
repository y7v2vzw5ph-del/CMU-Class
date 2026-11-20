"""Tests for loading the skills (shared/skills.py) and for the skill files themselves."""

import pytest

from shared.skills import get_skill, is_triggered, load_skills
from systems_expert.agent import industry_categories
from systems_expert.diagram import INDUSTRY_STYLES, style_key


def test_every_skill_file_loads_with_a_name_and_instructions():
    skills = load_skills()
    assert skills, "no skills found: is the skills folder where shared/skills.py expects it?"
    for skill in skills:
        assert skill["name"]
        assert skill["instructions"]


def test_missing_skill_raises_a_clear_error():
    with pytest.raises(FileNotFoundError):
        get_skill("no-such-skill")


def test_cvecheck_trigger_is_case_insensitive():
    skill = get_skill("vulnerability-intake")
    assert is_triggered(skill, ["CVECheck my systems"])
    assert is_triggered(skill, ["please cvecheck this"])
    assert not is_triggered(skill, ["what is the weather"])


def test_cvetask_is_not_a_trigger_word():
    # Documents the earlier surprise: only the exact word(s) in the skill's `triggers:` line count.
    assert not is_triggered(get_skill("vulnerability-intake"), ["cvetask ring camera"])


def test_intake_skill_asks_only_for_systems():
    meta = get_skill("vulnerability-intake")["meta"]
    assert "question_systems" in meta
    assert "question_connection" not in meta


def test_every_industry_category_has_a_diagram_colour():
    categories = industry_categories(get_skill("system-industry"))
    assert categories
    for category in categories:
        assert style_key(category) in INDUSTRY_STYLES
        assert style_key(category) == category.lower().replace(" ", "")  # a style of its own, not the fallback
