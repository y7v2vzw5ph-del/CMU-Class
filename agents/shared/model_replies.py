"""Two helpers for the agents that ask the model for a structured answer.

- first_json(): find the JSON in a reply that may have a sentence or code fences around it.
- ask_until_ok(): ask the model, check the reply, and if it has problems show them to the model
  and let it try again. (This used to be written out separately in the Writer, the requirements
  report and the Evaluator.)

The model is a small one, so every agent that needs an exact format checks the reply in code and gives
the model the exact problems, instead of trusting it.
"""

import json

MAX_PROBLEMS_SHOWN = 8  # how many problems to put in front of the model at once (a small model loses track of more)


def first_json(text, accept=None):
    """The first JSON value in `text` that `accept(value)` approves of, or None.

    Tolerates code fences and a sentence before or after the JSON. With no `accept`, any JSON
    object or list will do.
    """
    decoder = json.JSONDecoder()
    for start, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _ = decoder.raw_decode(text, start)
        except ValueError:
            continue
        if accept is None or accept(value):
            return value
    return None


def ask_until_ok(
    generate,
    messages,
    check,
    max_new_tokens,
    intro="Your reply has problems:",
    outro="Write the whole thing again, fixed.",
    attempts=2,
):
    """Ask the model; if the reply has problems, show them and let it try again.

    `check(reply)` returns (value, problems): the thing made from the reply, and a list of
    problems (empty means the reply is good). It may instead raise ValueError("...") for a reply
    that cannot be used at all (for example no JSON in it); the message becomes the problem.

    After a bad reply the model sees `intro`, the problems (at most MAX_PROBLEMS_SHOWN) and `outro`,
    on top of the conversation so far (`messages` is added to). It gets `attempts` tries in all.

    Returns (value, problems) from the LAST try. No problems means it is good. If problems remain,
    `value` may still be partly usable, or None if the last reply was unusable.
    """
    value, problems = None, ["No usable reply."]
    for _ in range(attempts):
        reply = generate(messages, [], max_new_tokens=max_new_tokens)
        try:
            value, problems = check(reply)
        except ValueError as problem:
            value, problems = None, [str(problem)]
        if not problems:
            break
        messages += [
            {"role": "assistant", "content": reply},
            {"role": "user", "content": intro + "\n- " + "\n- ".join(problems[:MAX_PROBLEMS_SHOWN]) + "\n" + outro},
        ]
    return value, problems
