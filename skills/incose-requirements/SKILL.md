---
name: incose-requirements
description: Used by the Vulnerability Expert. Turns ONE CVE record into INCOSE-style "shall" requirements, returned as a JSON list. Also rewrites them when the Evaluator finds problems. Runs only after the user says yes to the offer under the vulnerability table.
triggers:
---

You will be given ONE CVE record (id, description, affected system, CWE).
Write the requirements that stop this weakness from happening. A CVE says
what went wrong. A requirement says what the system shall do so it cannot
go wrong that way. Do not copy the CVE text and do not say "upgrade to
version X".

How to write each requirement:
- Pattern: [condition,] the <specific part of the system> shall <do something>
  <to something> [measurable limit].
- Use the word "shall". Never use should, will, must or may.
- One requirement says ONE thing. If two parts could pass or fail on their
  own, write two requirements.
- Name the specific part of the system that acts (for example "the web
  interface of the Cisco RV340"). Do not write "it". Use the same name for
  the same part every time.
- Make it testable: give a number with a unit, an error code, or a clear
  pass or fail result.
- Never use: and/or, etc., TBD, adequate, appropriate, robust, fast, secure,
  user-friendly, easy, "as needed", "where possible".
- Say what the system shall do (positive form). Use "shall not" only for a
  true prohibition.
- Do not make up facts. If the CVE does not give a number or detail, make a
  sensible choice and write it in "assumptions".

Reply with ONLY a JSON list. No introduction, no code fences. Each item has
exactly these fields:
- id: REQ-001, REQ-002, ... (use the starting number you are given)
- component: the affected system
- statement: the "shall" sentence
- rationale: one sentence on why it is needed
- sources: {"cves": ["CVE-..."], "cwes": ["CWE-..."]} (copy the "cwes" from the record; if it
  has none, write an empty list. Never guess a CWE.)
- verification: {"method": "Test" or "Inspection" or "Analysis" or "Demonstration", "criterion": "the pass condition"}
- assumptions: a list of strings (an empty list if none)
- gate_status: "passed"

Code checks your answer. If you are given a list of errors, fix only those
problems and reply with the corrected JSON list again.

Rewriting: you may also be shown your earlier requirements for the CVE and
the problems the Evaluator found. Then write the requirements for that CVE
again, fixing every problem. Keep the ids you used before. Do not argue with
the Evaluator and do not add new topics.

Example. Input:
CVE-2023-12345: Buffer overflow in ExampleApp 2.1 file importer lets a remote
attacker run code with an overly long filename field. CWE-787.

Output:
[{"id": "REQ-001", "component": "ExampleApp 2.1", "statement": "When the file importer of ExampleApp 2.1 reads a file header, the file importer shall reject each filename field longer than 255 bytes.", "rationale": "An unbounded filename field allows out-of-bounds writes.", "sources": {"cves": ["CVE-2023-12345"], "cwes": ["CWE-787"]}, "verification": {"method": "Test", "criterion": "A 255-byte filename is accepted and a 256-byte filename is rejected with no memory fault."}, "assumptions": ["The 255-byte limit is assumed because the CVE gives no value."], "gate_status": "passed"}]
