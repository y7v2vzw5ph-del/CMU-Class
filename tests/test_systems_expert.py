"""Tests for the Systems Expert (systems_expert/agent.py). A fake model stands in for the real one."""

import threading
import time

from systems_expert.agent import (
    classify_industry,
    decide_cve,
    detect_industry,
    detect_scope,
    draw_diagram,
    intake,
    merge_systems,
    parse_systems,
    parse_verdict,
    revise,
    run_model_calls,
    strip_trigger_words,
    verify_cves,
)
from shared.skills import get_skill

INTAKE_SKILL = get_skill("vulnerability-intake")  # its `triggers:` line is "cvecheck"

CATEGORIES = ["IoT", "Wearables", "Fintech", "Software", "Hardware", "Networking", "Other"]
SYSTEMS = ["Ring Camera", "Cisco RV340", "Windows 11 laptop"]
INFO = {
    "systems": SYSTEMS,
    "count": 3,
    "scope": "many",
    "industry": {"Ring Camera": "IoT", "Cisco RV340": "Networking", "Windows 11 laptop": "Software"},
}


def no_systems(messages, tools, **kwargs):
    """A fake model that finds no systems in anything."""
    return '{"systems": []}'


# ---- Reading the user's words ---------------------------------------------------

def test_parse_systems_drops_names_the_user_never_typed():
    reply = '{"systems": ["Ring Camera", "Totally Made Up Router 9000"]}'
    assert parse_systems(reply, "check my Ring Camera please") == ["Ring Camera"]


def test_parse_systems_survives_garbage():
    assert parse_systems("not json at all", "anything") == []
    assert parse_systems('{"systems": "Ring Camera"}', "Ring Camera") == ["Ring Camera"]


# ---- The word that starts a check is never a system ----------------------------------

def test_the_trigger_word_is_removed_whatever_its_case_or_punctuation():
    strip = lambda text: strip_trigger_words(text, INTAKE_SKILL)  # noqa: E731
    assert strip("CVECheck nighthawk r7800 and ring doorbell camera") == "nighthawk r7800 and ring doorbell camera"
    assert strip("cvecheck: my Ring Camera") == "my Ring Camera"
    assert strip("Please CVEcheck, the Cisco RV340") == "Please the Cisco RV340"
    assert strip("CVECheck") == ""  # nothing is left
    assert strip("Ring Camera") == "Ring Camera"  # no trigger word: unchanged


def test_words_that_only_contain_the_trigger_are_left_alone():
    assert strip_trigger_words("CVEchecker 2.0 and my router", INTAKE_SKILL) == "CVEchecker 2.0 and my router"


def test_the_words_come_from_the_skills_triggers_line():
    assert strip_trigger_words("scan the Ring Camera", {"triggers": ["scan"]}) == "the Ring Camera"
    assert strip_trigger_words("scan the Ring Camera", {"triggers": []}) == "scan the Ring Camera"  # none: untouched
    assert strip_trigger_words("check up", {"triggers": ["check up"]}) == ""  # a trigger of several words


def test_parse_systems_removes_the_trigger_word_the_model_listed_as_a_system():
    user_text = "CVECheck nighthawk r7800 and ring doorbell camera"
    reply = '{"systems": ["CVECheck", "nighthawk r7800", "ring doorbell camera"]}'
    assert parse_systems(reply, user_text, INTAKE_SKILL) == ["nighthawk r7800", "ring doorbell camera"]
    # ...and keeps the rest of a name the model glued it onto, instead of losing the system
    glued = '{"systems": ["CVECheck nighthawk r7800", "ring doorbell camera"]}'
    assert parse_systems(glued, strip_trigger_words(user_text, INTAKE_SKILL), INTAKE_SKILL) == [
        "nighthawk r7800", "ring doorbell camera"]


def test_the_model_is_never_shown_the_trigger_word_and_cannot_list_it():
    seen = []

    def model_that_lists_cvecheck(messages, tools, **kwargs):
        seen.append(messages[-1]["content"])
        # What the user actually got back: the trigger word listed as a system.
        return '{"systems": ["CVECheck", "nighthawk r7800", "ring doorbell camera"]}'

    result = intake(model_that_lists_cvecheck, [
        {"role": "user", "content": "CVECheck nighthawk r7800 and ring doorbell camera"}])
    assert result["info"]["systems"] == ["nighthawk r7800", "ring doorbell camera"]
    assert result["info"]["count"] == 2 and result["info"]["scope"] == "many"
    assert not any("cvecheck" in text.lower() for text in seen)  # the model only saw the systems


def test_a_bare_cvecheck_asks_which_systems_without_asking_the_model():
    def explode(messages, tools, **kwargs):
        raise AssertionError("nothing to extract, so the model must not be called")

    result = intake(explode, [{"role": "user", "content": "CVECheck"}])
    assert result["complete"] is False and "Which systems" in result["question"]


def test_the_trigger_word_in_an_earlier_message_is_removed_too():
    def model(messages, tools, **kwargs):
        text = messages[-1]["content"]
        assert "cvecheck" not in text.lower()
        return '{"systems": ["Ring Camera"]}' if "Ring" in text else '{"systems": ["Cisco RV340"]}'

    result = intake(model, [
        {"role": "user", "content": "CVECheck my Ring Camera"},
        {"role": "assistant", "content": "Anything else?"},
        {"role": "user", "content": "cvecheck the Cisco RV340 too"},
    ])
    assert result["info"]["systems"] == ["Ring Camera", "Cisco RV340"]


def test_merge_systems_keeps_the_more_specific_name():
    found = ["Windows 11"]
    merge_systems(found, ["Windows 11 22H2"])
    assert found == ["Windows 11 22H2"]
    merge_systems(found, ["Windows 11"])  # less specific: ignored
    assert found == ["Windows 11 22H2"]


def test_detect_scope():
    assert detect_scope("", ["a", "b"]) == "many"
    assert detect_scope("", ["a"]) == "one"
    assert detect_scope("many", []) == "many"
    assert detect_scope("", []) is None


def test_detect_industry_needs_the_right_words():
    assert detect_industry("the Ring camera is IoT") == "IoT"
    assert detect_industry("the Cisco RV340 is Networking") == "Networking"
    assert detect_industry("add a network camera") is None  # "network" inside a name


# ---- The intake ------------------------------------------------------------------

def test_intake_asks_for_systems_when_none_named():
    result = intake(no_systems, [{"role": "user", "content": "CVECheck"}])
    assert result["complete"] is False
    assert "Which systems" in result["question"]


def test_intake_completes_with_systems_and_never_asks_about_connections():
    def fake(messages, tools, **kwargs):
        return '{"systems": ["Ring Camera", "Cisco RV340"]}'

    result = intake(fake, [{"role": "user", "content": "CVECheck Ring Camera and Cisco RV340"}])
    assert result["complete"] is True
    assert result["info"]["systems"] == ["Ring Camera", "Cisco RV340"]
    assert result["info"]["scope"] == "many"
    assert "connection" not in result["info"]


# ---- The diagram node ------------------------------------------------------------

def test_draw_diagram_uses_the_industry_labels():
    diagram = draw_diagram(INFO)
    assert diagram["source"] == "code"
    assert "S1 --- S2" in diagram["mermaid"]  # camera -> router
    assert "Network" not in diagram["mermaid"]


# ---- Corrections -----------------------------------------------------------------

def test_revise_changes_an_industry():
    result = revise(no_systems, INFO, "the Ring Camera is Software")
    assert result["changed"] is True
    assert result["info"]["industry"]["Ring Camera"] == "Software"
    assert INFO["industry"]["Ring Camera"] == "IoT"  # the original is not modified


def test_revise_networking_label_changes_what_is_connected():
    result = revise(no_systems, INFO, "the Cisco RV340 is Hardware")
    assert result["changed"] is True
    from systems_expert.diagram import auto_edges
    assert auto_edges(result["info"]["systems"], result["info"]["industry"]) == []


def test_revise_removes_a_system_by_name():
    result = revise(no_systems, INFO, "remove Cisco")
    assert result["changed"] is True
    assert result["info"]["systems"] == ["Ring Camera", "Windows 11 laptop"]
    assert "Cisco RV340" not in result["info"]["industry"]
    assert result["info"]["count"] == 2


def test_revise_cannot_remove_everything():
    result = revise(no_systems, INFO, "remove Ring Cisco Windows")
    assert result["changed"] is False
    assert "every system" in result["message"]


def test_revise_adds_a_system_and_labels_it():
    def fake(messages, tools, **kwargs):
        system_text = messages[0]["content"]
        if "category" in system_text.lower() and "Reply with the category" in messages[-1]["content"]:
            return "Networking"
        return '{"systems": ["Netgear Nighthawk R7800"]}'

    result = revise(fake, INFO, "add a Netgear Nighthawk R7800")
    assert result["changed"] is True
    assert "Netgear Nighthawk R7800" in result["info"]["systems"]
    assert result["info"]["industry"]["Netgear Nighthawk R7800"] == "Networking"


def test_revise_says_how_to_phrase_when_it_cannot_tell():
    result = revise(no_systems, INFO, "hmm, something is off")
    assert result["changed"] is False
    assert "exactly as shown in the diagram" in result["message"]


def test_old_connection_wording_is_not_a_correction_any_more():
    for text in ("the laptop is wireless", "the Ring Camera connects to the Cisco RV340"):
        assert revise(no_systems, INFO, text)["changed"] is False


# ---- Checking CVE records --------------------------------------------------------

def test_parse_verdict_accepts_only_allowed_words():
    verdict = parse_verdict('{"product_family": "same", "cve_industry": "Software", "reason": ""}', CATEGORIES)
    assert verdict == {"product_family": "same", "cve_industry": "Software", "reason": ""}
    odd = parse_verdict('{"product_family": "banana", "cve_industry": "Sports"}', CATEGORIES)
    assert odd["product_family"] == "unknown" and odd["cve_industry"] == "unknown"


def test_parse_verdict_unreadable_is_none():
    assert parse_verdict("sorry I cannot", CATEGORIES) is None
    assert parse_verdict("{bad json", CATEGORIES) is None


def test_parse_verdict_shortens_the_reason():
    long_reason = " ".join(["word"] * 40)
    verdict = parse_verdict(
        f'{{"product_family": "different", "cve_industry": "Software", "reason": "{long_reason}"}}', CATEGORIES
    )
    assert len(verdict["reason"].split()) == 12


def test_decide_cve_rules():
    different = {"product_family": "different", "cve_industry": "Software", "reason": "Other product"}
    assert decide_cve(different, "IoT") == ("excluded", "Other product")

    other_industry = {"product_family": "same", "cve_industry": "Software", "reason": ""}
    assert decide_cve(other_industry, "IoT")[0] == "demoted"

    same_industry = {"product_family": "same", "cve_industry": "IoT", "reason": ""}
    assert decide_cve(same_industry, "IoT") == ("kept", "")

    unsure = {"product_family": "unknown", "cve_industry": "unknown", "reason": ""}
    assert decide_cve(unsure, "IoT") == ("kept", "")  # never hide a record because we are unsure
    assert decide_cve(other_industry, "Other")[0] == "kept"  # an 'Other' label says nothing
    assert decide_cve(other_industry, None)[0] == "kept"


def _rows():
    return [
        {"system": "Ring Camera", "cve_id": "CVE-1", "description": "Ring doorbell flaw", "cvss": 9.0},
        {"system": "Ring Camera", "cve_id": "CVE-2", "description": "RingCentral Desktop flaw", "cvss": 8.0},
        {"system": "Ring Camera", "cve_id": "CVE-3", "description": "Something unclear", "cvss": 7.0},
        {"system": "Ring Camera", "cve_id": "CVE-4", "description": "A Windows driver", "cvss": 6.0},
    ]


def _verdict_model(messages, tools, **kwargs):
    text = messages[-1]["content"]
    if "RingCentral" in text:
        return '{"product_family": "different", "cve_industry": "Software", "reason": "Phone software"}'
    if "unclear" in text:
        return "I am not sure"  # unreadable
    if "Windows" in text:
        return '{"product_family": "same", "cve_industry": "Software", "reason": ""}'
    return '{"product_family": "same", "cve_industry": "IoT", "reason": ""}'


def test_verify_cves_sorts_records_into_the_right_lists():
    verdict = verify_cves(_verdict_model, {"rows": _rows()}, {"Ring Camera": "IoT"})
    assert [r["cve_id"] for r in verdict["kept"]] == ["CVE-1", "CVE-3"]  # CVE-3: unreadable -> kept
    assert verdict["unverified"] == ["CVE-3"]
    assert [e["cve_id"] for e in verdict["excluded"]] == ["CVE-2"]
    assert [d["cve_id"] for d in verdict["demoted"]] == ["CVE-4"]


# ---- Running model calls at the same time ----------------------------------------

def _counting_model():
    """A fake model that records how many calls were running at once."""
    state = {"now": 0, "max": 0}
    lock = threading.Lock()

    def generate(messages, tools, **kwargs):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.05)
        with lock:
            state["now"] -= 1
        return _verdict_model(messages, tools, **kwargs)

    return generate, state


def test_calls_run_one_by_one_without_max_parallel():
    generate, state = _counting_model()
    run_model_calls(generate, lambda row: generate([{"content": row}], []), ["a", "b", "c", "d"])
    assert state["max"] == 1


def test_calls_run_together_with_max_parallel():
    generate, state = _counting_model()
    generate.max_parallel = 4
    run_model_calls(generate, lambda row: generate([{"content": row}], []), ["a", "b", "c", "d"])
    assert state["max"] > 1


def test_parallel_results_keep_their_order():
    def slow_first(item):
        time.sleep(0.1 if item == 1 else 0.0)  # item 1 finishes last
        return item

    def generate(messages, tools, **kwargs):
        return ""

    generate.max_parallel = 4
    assert run_model_calls(generate, slow_first, [1, 2, 3, 4]) == [1, 2, 3, 4]


def test_parallel_verification_gives_the_same_answer_as_serial():
    serial = verify_cves(_verdict_model, {"rows": _rows()}, {"Ring Camera": "IoT"})
    generate, _ = _counting_model()
    generate.max_parallel = 4
    parallel = verify_cves(generate, {"rows": _rows()}, {"Ring Camera": "IoT"})
    assert parallel == serial


def test_classify_industry_labels_every_system_even_in_parallel():
    def fake(messages, tools, **kwargs):
        name = messages[-1]["content"]
        return "Networking" if "Cisco" in name else "Banana"  # outside the list -> Other

    fake.max_parallel = 3
    labels = classify_industry(fake, SYSTEMS)
    assert labels == {"Ring Camera": "Other", "Cisco RV340": "Networking", "Windows 11 laptop": "Other"}
    assert list(labels) == SYSTEMS  # same order as the systems
