"""Tests for the shared helpers for the model's replies (shared/model_replies.py)."""

import pytest

from shared.model_replies import MAX_PROBLEMS_SHOWN, ask_until_ok, first_json


# ---- first_json ---------------------------------------------------------------------

def test_first_json_finds_an_object_or_a_list_inside_fences_and_chatter():
    assert first_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert first_json('Sure! Here you go: [{"a": 1}, {"a": 2}] Hope that helps.') == [{"a": 1}, {"a": 2}]
    assert first_json('noise {"broken": ') is None  # nothing complete in it
    assert first_json("no json at all") is None and first_json("") is None


def test_first_json_returns_the_first_value_the_caller_accepts():
    text = '[1, 2] then {"kind": "wanted"} then {"kind": "later"}'
    assert first_json(text) == [1, 2]  # with no filter, the first JSON value
    only_objects = lambda value: isinstance(value, dict)  # noqa: E731
    assert first_json(text, only_objects) == {"kind": "wanted"}
    assert first_json("[1, 2]", only_objects) is None


def test_first_json_looks_inside_a_list_for_an_object_when_only_objects_are_wanted():
    assert first_json('[{"a": 1}]', lambda value: isinstance(value, dict)) == {"a": 1}


# ---- ask_until_ok ---------------------------------------------------------------------

class Replies:
    """A fake model that answers from a list (the last answer repeats) and remembers every call."""

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, messages, tools, **kwargs):
        self.calls.append(([dict(m) for m in messages], kwargs))
        return self.replies[min(len(self.calls), len(self.replies)) - 1]


def check_is_ok(reply):
    return reply.upper(), ([] if reply == "ok" else [f"'{reply}' is not ok"])


def test_a_good_first_reply_is_used_without_a_second_question():
    model = Replies("ok")
    assert ask_until_ok(model, [{"role": "user", "content": "q"}], check_is_ok, 50) == ("OK", [])
    assert len(model.calls) == 1 and model.calls[0][1] == {"max_new_tokens": 50}


def test_the_model_is_shown_the_problems_and_a_second_reply_can_fix_it():
    model = Replies("bad", "ok")
    messages = [{"role": "user", "content": "q"}]
    value, problems = ask_until_ok(model, messages, check_is_ok, 50, intro="Problems:", outro="Try again.")
    assert (value, problems) == ("OK", [])
    follow_up = model.calls[1][0]  # what the model saw the second time
    assert [m["role"] for m in follow_up] == ["user", "assistant", "user"]
    assert follow_up[1]["content"] == "bad"  # its own bad reply
    assert follow_up[2]["content"] == "Problems:\n- 'bad' is not ok\nTry again."


def test_when_it_never_gets_it_right_the_last_value_and_its_problems_come_back():
    model = Replies("bad", "worse")
    value, problems = ask_until_ok(model, [], check_is_ok, 50)
    assert (value, problems) == ("WORSE", ["'worse' is not ok"])  # partly usable values are kept
    assert len(model.calls) == 2  # two tries by default, no more


def test_the_number_of_tries_can_be_set():
    model = Replies("bad")
    ask_until_ok(model, [], check_is_ok, 50, attempts=3)
    assert len(model.calls) == 3


def test_an_unusable_reply_raises_valueerror_and_its_message_is_shown_to_the_model():
    def check(reply):
        if "{" not in reply:
            raise ValueError("Reply with JSON.")
        return reply, []

    model = Replies("words", "{}")
    assert ask_until_ok(model, [], check, 50) == ("{}", [])
    assert "Reply with JSON." in model.calls[1][0][-1]["content"]

    value, problems = ask_until_ok(Replies("words"), [], check, 50)
    assert value is None and problems == ["Reply with JSON."]  # never usable: no value


def test_only_the_first_problems_are_shown_so_a_small_model_is_not_flooded():
    many = [f"problem {i}" for i in range(MAX_PROBLEMS_SHOWN + 5)]
    model = Replies("x")
    ask_until_ok(model, [], lambda reply: (reply, many), 50)
    shown = model.calls[1][0][-1]["content"]
    assert f"problem {MAX_PROBLEMS_SHOWN - 1}" in shown and f"problem {MAX_PROBLEMS_SHOWN}" not in shown


@pytest.mark.parametrize("attempts", [1, 2, 3])
def test_it_stops_asking_as_soon_as_a_reply_is_good(attempts):
    model = Replies("bad", "ok", "ok")
    ask_until_ok(model, [], check_is_ok, 50, attempts=attempts)
    assert len(model.calls) == min(attempts, 2)
