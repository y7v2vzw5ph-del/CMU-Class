"""Systems Expert (SE) agent.

Job (Stage 1): run the "vulnerability-intake" skill. The SE reads the chat and
works out which systems the user has. It tells the Router what to ask the user
next, or that it has everything.

Why it's split between code and the model: a small 3B model was unreliable at
doing the whole job (it echoed the user, re-asked answered questions and
renamed products). So:
- plain code spots "one/many" in the user's words and picks the next question
  (the wording comes from the skill's header);
- the model only does the part that needs understanding: pulling the system
  names out of the user's messages. Code then checks every name really appeared
  in what the user typed, so the model can't invent systems.

Job (Stage 4): once the intake is finished, draw the systems as a block diagram
(Mermaid text). Plain code builds it, with no model: every system is joined by a
solid line to the networking device (the system whose industry is Networking);
with no networking device nothing is joined. Each box is coloured by its industry
(see diagram.py).

In the LangGraph (router/graph.py) this agent is two nodes:
- intake(generate, conversation): the Stage 1 intake, returns what to ask next
- draw_diagram(info): the Stage 4 diagram
"""

import json
import re
from concurrent.futures import ThreadPoolExecutor

from shared.skills import get_skill
from systems_expert.diagram import build_diagram

NAME = "Systems Expert"

SYSTEM_PROMPT = (
    "You are the Systems Expert (SE) on a team of security agents. "
    "You read what the user wrote and extract the systems they named. "
)

JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def run_model_calls(generate, work, items):
    """work(item) for every item, in order. Returns the results in the same order.

    Items run at the same time if the backend says it can handle that: the
    backend sets `generate.max_parallel` (the Colab GPU server does). A `generate`
    without it (like a fake model in a test) runs one by one.
    """
    items = list(items)
    workers = min(getattr(generate, "max_parallel", 1), len(items))
    if workers <= 1:
        return [work(item) for item in items]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(work, items))  # map keeps the original order

# ---- Spotting answers in the user's words (plain code) --------------------------
NOUNS = r"(?:systems?|servers?|machines?|devices?|computers?|hosts?)"
ONE_RE = re.compile(rf"\b(?:one|single)\b|\b1\s+{NOUNS}\b")
MANY_RE = re.compile(rf"\b(?:many|multiple|several|couple)\b|\b(?:[2-9]|\d{{2,}})\s+{NOUNS}\b")


def detect_scope(text, systems):
    """'one' or 'many', from the user's words or from how many systems they listed."""
    text = text.lower()
    if len(systems) > 1 or MANY_RE.search(text):
        return "many"
    if ONE_RE.search(text) or len(systems) == 1:
        return "one"
    return None


# ---- The model's part: system names -------------------------------------------

def tokens(text):
    return set(re.findall(r"[a-z0-9.]+", text.lower()))


def is_short_answer(message):
    """True for replies like 'many' or 'one'. Code handles those already."""
    text = message.lower()
    is_keyword = any(r.search(text) for r in (ONE_RE, MANY_RE))
    return is_keyword and len(text.split()) <= 3


def merge_systems(found, new_names):
    """Add names to the list, keeping the more specific one ('Windows 11 22H2' beats 'Windows 11')."""
    for name in new_names:
        name_tokens = tokens(name)
        if any(name_tokens <= tokens(existing) for existing in found):
            continue  # already have this one (or a more specific version of it)
        found[:] = [e for e in found if not tokens(e) <= name_tokens]
        found.append(name)
    return found


def strip_trigger_words(text, skill):
    """Remove the word that starts a check ("CVECheck") from `text`: it is a command, never a system.

    The words come from the skill's `triggers:` line, so this can never disagree with what starts a check.
    Case does not matter, and the rest is kept: "CVECheck nighthawk r7800" -> "nighthawk r7800".
    Words that merely CONTAIN a trigger ("cvechecker") are left alone.
    """
    if not skill["triggers"]:
        return text
    words = "|".join(re.escape(word) for word in skill["triggers"])
    cleaned = re.sub(rf"\b(?:{words})\b[,:;]?", " ", text, flags=re.IGNORECASE)  # and a comma or colon right after it
    return " ".join(cleaned.split()).strip(" ,:;-")


def parse_systems(reply, user_text, skill=None):
    """Turn the model's JSON into a clean list, dropping anything the user never said.

    With the intake `skill`, the trigger word is also taken out of every name the model gives
    (the model sometimes lists "CVECheck" itself as a system).
    """
    match = JSON_RE.search(reply)
    try:
        data = json.loads(match.group(0)) if match else {}
    except json.JSONDecodeError:
        data = {}
    raw = data.get("systems") if isinstance(data, dict) else None
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []

    user_tokens = tokens(user_text)
    systems = []
    for item in raw:
        name = strip_trigger_words(str(item), skill) if skill else str(item)
        name = name.strip()
        # Every word/number in the name must appear in what the user typed.
        if name and tokens(name) <= user_tokens and name.lower() not in [s.lower() for s in systems]:
            systems.append(name)
    return systems


# ---- Industry category of each system (confirmed by the user before any CVE pull) ----

INDUSTRY_MAX_NEW_TOKENS = 6  # the answer is one word
FALLBACK_INDUSTRY = "Other"

# How a user might name each category when correcting us ("the Ring camera is IoT").
# The labels must match the `categories` line of the system-industry skill.
INDUSTRY_WORDS = {
    "IoT": r"iot|internet of things",
    "Wearables": r"wearables?",
    "Fintech": r"fintech|financial|finance|banking",
    "Software": r"software|operating system|os",
    "Hardware": r"hardware",
    "Networking": r"networking|network",
    "Other": r"other",
}


def industry_categories(skill):
    """The allowed categories, read from the skill's `categories` header line."""
    return [c.strip() for c in skill["meta"].get("categories", "").split(",") if c.strip()]


def parse_industry(reply, categories):
    """The model's one-word reply -> a category from the list ("Other" if it isn't one)."""
    text = reply.lower()
    best = None  # (position in the reply, category): the category named first wins
    for category in categories:
        found = re.search(rf"\b{re.escape(category.lower())}\b", text)
        if found and (best is None or found.start() < best[0]):
            best = (found.start(), category)
    return best[1] if best else FALLBACK_INDUSTRY


def classify_industry(generate, systems):
    """Use the system-industry skill to label each system. Returns {system: category}.

    One short model call per system (at the same time when the backend allows it).
    The model can only answer with a category from the skill's list: anything else
    becomes "Other".
    """
    skill = get_skill("system-industry")
    categories = industry_categories(skill)

    def label_one(name):
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + skill["instructions"]},
            {"role": "user", "content": f"System: {name}\n\nReply with the category only."},
        ]
        return parse_industry(generate(messages, [], max_new_tokens=INDUSTRY_MAX_NEW_TOKENS), categories)

    return dict(zip(systems, run_model_calls(generate, label_one, systems)))


def detect_industry(correction):
    """The category a correction asks for ("the Ring camera is IoT" -> "IoT"), or None.

    Needs "is / are / as / to / be" right before the category word, so a system
    name that happens to contain one ("add a network camera") doesn't trigger it.
    """
    text = correction.lower()
    for label, words in INDUSTRY_WORDS.items():
        if re.search(rf"\b(?:is|are|as|to|be)\s+(?:an?\s+|the\s+)?(?:{words})\b", text):
            return label
    return None


def draw_diagram(info):
    """Draw the systems. Every system is joined by a solid line to the networking device
    (the system whose industry is Networking); with none, nothing is joined. Each box is
    coloured by its industry. Plain code, no model (so no name can be dropped or invented).

    Returns {"mermaid": str, "source": "code"}.
    """
    return {"mermaid": build_diagram(info["systems"], info.get("industry")), "source": "code"}


def intake(generate, conversation):
    """Work out what we know so far and what to ask next.

    Returns {"complete": bool, "question": str or None, "info": {...}}.
    """
    skill = get_skill("vulnerability-intake")
    user_messages = [m["content"] for m in conversation if m["role"] == "user"]
    user_text = "\n".join(user_messages)

    # The model extracts system names from what the USER wrote (not our questions).
    # One message at a time: the 3B model is accurate on one message, but gets
    # confused when unrelated short replies ("many") are mixed in.
    systems = []
    for text in user_messages:
        # "CVECheck" starts the check; it is not a system, so the model never sees it.
        text = strip_trigger_words(text, skill)
        if not text or is_short_answer(text):
            continue  # nothing left (just "CVECheck"), or e.g. "many": the rules above already handle it
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + skill["instructions"]},
            {
                "role": "user",
                "content": f"The user's message:\n{text}\n\nReply with the JSON object only.",
            },
        ]
        merge_systems(systems, parse_systems(generate(messages, []), text, skill))

    info = {"scope": detect_scope(user_text, systems), "systems": systems}

    # Ask for the first missing item. Wording is in the skill header.
    # "One or many" is never asked: it is worked out from how many systems were named.
    if not systems:
        return {"complete": False, "question": skill["meta"]["question_systems"], "info": info}

    info["count"] = len(systems)
    return {"complete": True, "question": None, "info": info}


# ---- Corrections after the user sees the diagram ---------------------------------

REMOVE_RE = re.compile(r"\b(?:remove|delete|drop|take out|get rid of)\b")
ADD_RE = re.compile(r"\b(?:add|also|plus|include)\b")
ALL_RE = re.compile(r"\b(?:all|everything|every|each|them)\b")
# Words too general to identify one system ("the web server is IoT" names nothing).
GENERIC_WORDS = {
    "the", "a", "an", "and", "my", "server", "pc", "computer", "laptop", "desktop",
    "router", "camera", "phone", "device", "system", "web", "http",
}

CORRECTION_HELP = (
    "Use the system names exactly as shown in the diagram. You can say things like "
    '"the Ring Camera is IoT", "the Cisco RV340 is Networking", "remove Apache HTTP Server 2.4.57" '
    'or "add a Cisco RV340 router".'
)


def mentions(system, correction_tokens):
    """True if the correction names this system (by a word that identifies it)."""
    return bool((tokens(system) - GENERIC_WORDS) & correction_tokens)


def revise(generate, info, correction):
    """Apply the user's correction to the systems and their industries.

    Links are not edited: the diagram draws them from the industries (see diagram.py),
    so saying "the Cisco RV340 is Networking" is how the user changes what is connected.
    Returns {"changed": bool, "info": {...}, "message": str or None}.
    When nothing could be changed, `message` says what to try instead.
    Plain code does the work. The model is only used to read the names of
    systems the user adds (the same guarded extraction as the intake).
    """
    text = correction.lower()
    ctokens = tokens(correction)
    systems = list(info["systems"])
    changes = []

    def fail(message):
        return {"changed": False, "info": info, "message": message}

    # 1. Remove systems the user names.
    removed = False
    if REMOVE_RE.search(text):
        keep = [s for s in systems if not mentions(s, ctokens)]
        if not keep:
            return fail("That would remove every system. Say **cancel** to stop, or tell me what else to change.")
        if len(keep) < len(systems):
            removed = True
            changes += [s for s in systems if s not in keep]
            systems = keep

    # 2. Add systems (the model reads the names; code checks they appear in the text).
    added = []
    if ADD_RE.search(text) and not removed:
        skill = get_skill("vulnerability-intake")
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + skill["instructions"]},
            {"role": "user", "content": f"The user's message:\n{correction}\n\nReply with the JSON object only."},
        ]
        for name in parse_systems(generate(messages, []), correction):
            if any(tokens(name) <= tokens(existing) for existing in systems):
                continue  # already in the list
            systems.append(name)
            added.append(name)
        changes += [f"added {n}" for n in added]

    # 3. Industry categories: drop removed systems, label added ones, apply the user's fix.
    industry = {s: c for s, c in (info.get("industry") or {}).items() if s in systems}
    for name in added:
        industry[name] = classify_industry(generate, [name])[name]
    label = detect_industry(correction)
    if label:
        targets = [s for s in systems if mentions(s, ctokens)]
        if not targets and (ALL_RE.search(text) or len(systems) == 1):
            targets = list(systems)
        if not targets and not (added or removed):
            return fail(f"Which system is {label}? " + CORRECTION_HELP)
        for s in targets:
            if industry.get(s) != label:
                industry[s] = label
                changes.append(f"{s} is {label}")

    if not changes:
        return fail("I couldn't tell what to change. " + CORRECTION_HELP)

    new_info = dict(info)
    new_info.update(
        {
            "systems": systems,
            "count": len(systems),
            "scope": detect_scope("", systems),
            "industry": industry,
        }
    )
    return {"changed": True, "info": new_info, "message": None, "changes": changes}

# ---- Checking that CVE records really belong to the systems ----------------------

VERIFY_MAX_DESCRIPTION_CHARS = 500  # enough text to name the product, short enough for CPU
VERIFY_MAX_NEW_TOKENS = 80
MAX_REASON_WORDS = 12

FAMILY_LABELS = ("same", "related", "different", "unknown")
# A label that says nothing about the industry: never a reason to demote a CVE.
NO_INDUSTRY_INFO = {"unknown", FALLBACK_INDUSTRY.lower()}


def parse_verdict(reply, categories):
    """The model's JSON -> {"product_family", "cve_industry", "reason"}, or None if unreadable.

    The model can only use the allowed words. Anything else becomes "unknown",
    which later means "keep the record" (we never hide a CVE just because the
    model was unsure). Only a reply with neither label at all counts as unreadable.
    """
    found = JSON_RE.search(reply)
    try:
        data = json.loads(found.group(0)) if found else {}
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or not ("product_family" in data or "cve_industry" in data):
        return None
    family = str(data.get("product_family") or "").strip().lower()
    if family not in FAMILY_LABELS:
        family = "unknown"
    wanted = str(data.get("cve_industry") or "").strip().lower()
    industry = next((c for c in categories if c.lower() == wanted), "unknown")
    reason = " ".join(str(data.get("reason") or "").split()[:MAX_REASON_WORDS])
    return {"product_family": family, "cve_industry": industry, "reason": reason}


def decide_cve(verdict, system_industry):
    """Plain code: turn the model's labels into "kept", "excluded" or "demoted".

    - product family "different" -> excluded (a keyword collision, e.g. RingCentral for a Ring camera)
    - the CVE's industry clearly differs from the industry the user confirmed -> demoted
      (right vendor, different kind of product). Shown as an id + one short sentence.
    - anything else, including every "unknown" or "Other" -> kept.
    Returns (outcome, reason).
    """
    if verdict["product_family"] == "different":
        return "excluded", verdict["reason"] or "Different product from your system."
    cve_industry = verdict["cve_industry"]
    if (
        system_industry
        and system_industry.lower() not in NO_INDUSTRY_INFO
        and cve_industry.lower() not in NO_INDUSTRY_INFO
        and cve_industry.lower() != system_industry.lower()
    ):
        return "demoted", f"Record is about {cve_industry}; your system is {system_industry}."
    return "kept", ""


def judge_cve(generate, skill, categories, row):
    """Ask the model for the two labels for one CVE record. Returns the verdict dict, or None."""
    description = " ".join((row.get("description") or "").split())[:VERIFY_MAX_DESCRIPTION_CHARS]
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + skill["instructions"]},
        {
            "role": "user",
            "content": f"System: {row['system']}\nCategories: {', '.join(categories)}\n"
            f"{row['cve_id']}: {description}\n\nReply with the JSON object only.",
        },
    ]
    for _ in range(2):  # one retry if the answer can't be read
        verdict = parse_verdict(generate(messages, [], max_new_tokens=VERIFY_MAX_NEW_TOKENS), categories)
        if verdict is not None:
            return verdict
    return None


def verify_cves(generate, results, industry=None):
    """Use the cve-verification skill to check every CVE record against its system.

    `industry` is the user-confirmed {system: category} from the intake.
    Returns {"kept": [rows],
             "excluded": [{"system", "cve_id", "reason"}],   different product
             "demoted":  [{"system", "cve_id", "cvss", "reason"}],  different industry
             "unverified": [cve_id, ...]}.
    If the model's answer can't be read, the CVE is KEPT and listed as
    unverified: wrongly hiding a real vulnerability is worse than showing one extra.
    """
    skill = get_skill("cve-verification")
    categories = industry_categories(get_skill("system-industry"))
    industry = industry or {}
    kept, excluded, demoted, unverified = [], [], [], []
    # The slow part: one model call per CVE record. They can run at the same time
    # (see run_model_calls); the decisions below are then made in the original order.
    rows = results["rows"]
    verdicts = run_model_calls(generate, lambda row: judge_cve(generate, skill, categories, row), rows)
    for row, verdict in zip(rows, verdicts):
        if verdict is None:
            unverified.append(row["cve_id"])
            kept.append(row)
            continue
        outcome, reason = decide_cve(verdict, industry.get(row["system"]))
        if outcome == "excluded":
            excluded.append({"system": row["system"], "cve_id": row["cve_id"], "reason": reason})
        elif outcome == "demoted":
            demoted.append(
                {"system": row["system"], "cve_id": row["cve_id"], "cvss": row.get("cvss"), "reason": reason}
            )
        else:
            kept.append(row)
    return {"kept": kept, "excluded": excluded, "demoted": demoted, "unverified": unverified}
