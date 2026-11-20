"""Try the requirements loop on a few CVEs, with a real model, without the chat UI.

Run from the AIClass_PythonCode folder:

    uv run --project agents python try_requirements.py              # sample CVEs, model on Colab (from .env)
    uv run --project agents python try_requirements.py --cves my.json
    uv run --project agents python try_requirements.py --demo       # fake model: checks the plumbing only

It runs the very same LangGraph subgraph the chat does (router/requirements_graph.py). For each
component (one system), one after another:
  1. The Vulnerability Expert writes requirements, one CVE at a time (regex gate, up to 3 tries each).
  2. The Evaluator reviews them.
  3. If it found mistakes, the Vulnerability Expert rewrites those CVEs and the Evaluator reviews
     once more. At most 2 reviews.
Then the Writer formats the output (each component Pass or Needs review) with the requirements-table
and requirements-report skills, and the full results are saved as JSON in requirements_run/.

--cves takes a JSON list of objects like the sample CVEs below. The "system" field is the
component, so CVEs with the same system are written and reviewed together.
Colab: put COLAB_URL and COLAB_KEY in .env (same as CVE_TASK.py) and start the notebook first.
"""

import argparse
import json
import time
from pathlib import Path

from dotenv import dotenv_values

from router.requirements_graph import MAX_REVIEWS, run_requirements
from writer.requirements_report import build_requirements_report

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "requirements_run"

# Sample data: short paraphrases written for this exercise, not copied NVD text.
# Check any CVE against https://nvd.nist.gov before relying on it.
SAMPLE_CVES = [
    {
        "cve_id": "CVE-2021-44228", "system": "Apache Log4j 2.14", "cvss": 10.0, "severity": "CRITICAL", "cwe": "CWE-502",
        "description": "Log4j resolves lookup expressions inside logged messages. A remote attacker who "
                       "controls text that gets logged can make it load and run code from a remote server.",
    },
    {
        "cve_id": "CVE-2014-0160", "system": "OpenSSL 1.0.1", "cvss": 7.5, "severity": "HIGH", "cwe": "CWE-119",
        "description": "The TLS heartbeat extension does not check the length a peer claims for its payload, "
                       "so a remote peer can read memory beyond the payload and leak private data such as keys.",
    },
    {
        "cve_id": "CVE-2017-5638", "system": "Apache Struts 2.3", "cvss": 10.0, "severity": "CRITICAL", "cwe": "CWE-20",
        "description": "The file upload parser mishandles a crafted Content-Type header, letting a remote "
                       "attacker run commands on the server.",
    },
    {
        "cve_id": "CVE-2023-4863", "system": "libwebp 1.3", "cvss": 8.8, "severity": "HIGH", "cwe": "CWE-787",
        "description": "Decoding a crafted WebP image writes past the end of a heap buffer, which can lead to "
                       "code execution when an application opens an image from an untrusted source.",
    },
]


# ---- The fake model for --demo ------------------------------------------------

def demo_generator(messages, tools, **kwargs):
    """Not a real model. Answers just well enough to show the plumbing and the report format."""
    prompt = messages[-1]["content"]
    if prompt.startswith("CVE record"):  # the Vulnerability Expert
        record = json.loads(prompt.split("(JSON):\n", 1)[1].split("\n\nStart numbering", 1)[0])
        return json.dumps([{
            "id": "REQ-001", "component": record["system"],
            "statement": f"When {record['system']} receives untrusted input, {record['system']} shall reject "
                         f"input that triggers {record['cve_id']}.",
            "rationale": "Demo only.", "sources": {"cves": [record["cve_id"]], "cwes": record["cwes"]},
            "verification": {"method": "Test", "criterion": "The crafted input is rejected."},
            "assumptions": ["DEMO output, not written by a model."], "gate_status": "passed",
        }])
    reqs = json.loads(prompt.split("Requirements (JSON):\n", 1)[1].split("\n\nCVE records", 1)[0])  # the Evaluator
    return json.dumps({"requirements": [
        {"id": r["id"], "quote": r["statement"], "reasoning": "DEMO: not judged by a model.",
         "problems": [], "verdict": "pass", "severity": "none", "suggested_rewrite": ""} for r in reqs]})


def timed(generate):
    """Wrap a generator to count calls and time spent (shown at the end)."""
    stats = {"calls": 0, "seconds": 0.0}

    def wrapper(messages, tools, **kwargs):
        start = time.time()
        stats["calls"] += 1
        print(f"  model call {stats['calls']}...", end="\r", flush=True)
        try:
            return generate(messages, tools, **kwargs)
        finally:
            stats["seconds"] += time.time() - start

    wrapper.stats = stats
    return wrapper


def pick_generator(args):
    if args.demo:
        return demo_generator, "DEMO (fake model: this checks the plumbing, not model quality)"
    from router.agent import MODEL_ID, remote_generator  # heavy import

    env = dotenv_values(HERE / ".env")
    if env.get("COLAB_URL") and env.get("COLAB_KEY"):
        return remote_generator(env["COLAB_URL"], env["COLAB_KEY"]), f"{MODEL_ID} on Colab"
    raise SystemExit("No COLAB_URL / COLAB_KEY in .env. Fill them in (and start the Colab notebook), or use --demo.")


def show_progress(item):
    """One line per component, before the Writer's output."""
    wrote = ", ".join(f"{e['cve_id']} {e['status']} ({e['attempts']} tries)" for e in item["write_log"])
    print(f"{item['component']}: written [{wrote}]; reviewed {item['reviews_done']} of at most {MAX_REVIEWS} time(s); "
          f"Evaluator says {item['review']['overall']}")


def main():
    parser = argparse.ArgumentParser(description="Try the requirements loop.")
    parser.add_argument("--cves", type=Path, help="JSON file with a list of CVE records")
    parser.add_argument("--demo", action="store_true", help="use a fake model (no GPU or download needed)")
    args = parser.parse_args()

    cves = json.loads(args.cves.read_text(encoding="utf-8-sig")) if args.cves else SAMPLE_CVES
    generate, backend = pick_generator(args)
    generate = timed(generate)
    print(f"Backend: {backend}\nCVEs: {', '.join(c['cve_id'] for c in cves)}\n")

    # The same subgraph the chat runs (router/requirements_graph.py): one component (system) at a time.
    done = run_requirements(generate, cves)
    for item in done:
        show_progress(item)

    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "requirements.json").write_text(json.dumps(done, indent=2), encoding="utf-8")
    # The Writer formats with the requirements-table and requirements-report skills. The demo's
    # fake model cannot do that, so in --demo the plain-code version is printed instead.
    markdown, sources = build_requirements_report(None if args.demo else generate, done)
    print("\n" + markdown)
    if not args.demo:
        for component, s in sources.items():
            print(f"formatting for {component}: table by {s['table'] or 'n/a'}, section by {s['section']}")
    stats = generate.stats
    print(f"\n{stats['calls']} model calls, {stats['seconds']:.0f} s in the model. "
          f"Full results are in {OUT_DIR.name}/requirements.json")


if __name__ == "__main__":
    main()
