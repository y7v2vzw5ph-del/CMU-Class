"""Tests for the Writer (writer/agent.py): grouping the table by system and the zero-CVE warning."""

from writer.agent import (
    _assemble,
    build_table,
    check_table,
    group_rows_by_system,
    prepare_rows,
    write_report,
    zero_cve_warnings,
)

SYSTEMS = ["Ring Camera", "Cisco RV340", "Roborock S7"]


def row(system, cve_id, cvss):
    return {"system": system, "cve_id": cve_id, "description": "text", "cvss": cvss, "severity": "HIGH"}


# ---- The CWE column ---------------------------------------------------------------

def test_the_table_shows_the_cwes_and_na_when_there_are_none():
    rows = [{**row("Ring Camera", "CVE-A", 9.8), "cwes": ["CWE-787", "CWE-20"]}, row("Ring Camera", "CVE-B", 5.0)]
    lines = build_table(prepare_rows(rows)).splitlines()
    assert lines[0] == "| # | System | CVE ID | CWE | Description | CVSS | Severity |"
    assert lines[2] == "| 1 | Ring Camera | CVE-A | CWE-787, CWE-20 | text | 9.8 | HIGH |"
    assert lines[3] == "| 2 | Ring Camera | CVE-B | N/A | text | 5.0 | HIGH |"  # no CWE listed: N/A, never made up


def test_a_model_table_with_a_wrong_or_made_up_cwe_is_rejected():
    prepared = prepare_rows([{**row("Ring Camera", "CVE-A", 9.8), "cwes": ["CWE-787"]}, row("Ring Camera", "CVE-B", 5.0)])
    good = build_table(prepared)
    assert check_table(good, prepared) == []
    assert any("CWE must be CWE-787" in p for p in check_table(good.replace("CWE-787", "CWE-79"), prepared))
    assert any("CWE must be N/A" in p for p in check_table(good.replace("| N/A |", "| CWE-79 |"), prepared))  # invented
    old_layout = "\n".join(line.replace(" CWE-787 |", "").replace(" CWE |", "") for line in good.splitlines())
    assert any("must have 7 columns" in p for p in check_table(old_layout, prepared))


# ---- Grouping the table by system -----------------------------------------------

def test_rows_are_grouped_by_system_in_the_users_order():
    # The graph hands over rows worst-CVSS-first across all systems, so systems are mixed up.
    mixed = [
        row("Cisco RV340", "CVE-A", 9.8),
        row("Ring Camera", "CVE-B", 9.0),
        row("Cisco RV340", "CVE-C", 7.0),
        row("Ring Camera", "CVE-D", 5.0),
    ]
    grouped = group_rows_by_system(mixed, SYSTEMS)
    assert [r["cve_id"] for r in grouped] == ["CVE-B", "CVE-D", "CVE-A", "CVE-C"]  # Ring first, then Cisco


def test_grouping_keeps_the_worst_first_order_inside_a_system():
    rows = [row("Ring Camera", "CVE-1", 9.0), row("Cisco RV340", "CVE-2", 8.0), row("Ring Camera", "CVE-3", 4.0)]
    grouped = group_rows_by_system(rows, SYSTEMS)
    assert [r["cve_id"] for r in grouped if r["system"] == "Ring Camera"] == ["CVE-1", "CVE-3"]


def test_rows_for_unknown_systems_go_last_and_no_systems_changes_nothing():
    rows = [row("(direct lookup)", "CVE-X", 5.0), row("Ring Camera", "CVE-Y", 9.0)]
    assert [r["cve_id"] for r in group_rows_by_system(rows, SYSTEMS)] == ["CVE-Y", "CVE-X"]
    assert [r["cve_id"] for r in group_rows_by_system(rows, None)] == ["CVE-X", "CVE-Y"]


def test_the_table_is_numbered_after_grouping():
    mixed = [row("Cisco RV340", "CVE-A", 9.8), row("Ring Camera", "CVE-B", 9.0), row("Cisco RV340", "CVE-C", 7.0)]
    prepared = prepare_rows(group_rows_by_system(mixed, SYSTEMS))
    lines = build_table(prepared).splitlines()[2:]
    systems_in_order = [line.split("|")[2].strip() for line in lines]
    numbers = [line.split("|")[1].strip() for line in lines]
    assert systems_in_order == ["Ring Camera", "Cisco RV340", "Cisco RV340"]
    assert numbers == ["1", "2", "3"]


def test_write_report_groups_even_when_the_model_is_not_needed():
    mixed = [row("Cisco RV340", "CVE-A", 9.8), row("Ring Camera", "CVE-B", 9.0), row("Cisco RV340", "CVE-C", 7.0)]
    results = {"rows": mixed, "systems": SYSTEMS, "no_results": [], "errors": []}

    def bad_model(messages, tools, **kwargs):
        return "garbage"  # forces the code-built table

    report = write_report(bad_model, results)
    assert report["table_source"] == "code"
    text = report["markdown"]
    assert text.index("CVE-B") < text.index("CVE-A") < text.index("CVE-C")


# ---- The zero-CVE warning ---------------------------------------------------------

def base_results(**extra):
    results = {"rows": [], "systems": SYSTEMS, "no_results": [], "errors": []}
    results.update(extra)
    return results


def test_no_warning_when_every_system_has_cves():
    assert zero_cve_warnings(base_results()) == []


def test_warning_names_the_system_and_what_was_searched():
    results = base_results(no_results=["Roborock S7"], searched={"Roborock S7": ["Roborock S7", "Roborock"]})
    [warning] = zero_cve_warnings(results)
    assert "⚠️" in warning and "Roborock S7" in warning
    assert '"Roborock S7", then "Roborock"' in warning
    assert "spelled correctly" in warning
    assert "does not mean this system is secure" in warning


def test_warning_counts_records_that_were_filtered_out():
    results = base_results(
        no_results=["Ring Camera"],
        excluded=[
            {"system": "Ring Camera", "cve_id": "CVE-1", "reason": "RingCentral"},
            {"system": "Ring Camera", "cve_id": "CVE-2", "reason": "RingCentral"},
            {"system": "Cisco RV340", "cve_id": "CVE-3", "reason": "other"},  # not this system
        ],
        demoted=[{"system": "Ring Camera", "cve_id": "CVE-4", "cvss": 5.0, "reason": "software"}],
    )
    [warning] = zero_cve_warnings(results)
    assert "2 matched a keyword but were about other products" in warning
    assert "1 looked like the right vendor but a different kind of product" in warning


def test_one_warning_per_system_with_nothing():
    results = base_results(no_results=["Ring Camera", "Roborock S7"])
    assert len(zero_cve_warnings(results)) == 2


def test_cve_ids_from_a_direct_lookup_are_not_treated_as_systems():
    results = {"rows": [], "systems": [], "no_results": ["CVE-2099-0001"], "errors": []}
    assert zero_cve_warnings(results) == []
    assert "No CVEs found for: CVE-2099-0001" in _assemble(None, None, results)


def test_the_report_shows_the_warning():
    results = base_results(
        rows=[row("Ring Camera", "CVE-B", 9.0)],
        no_results=["Roborock S7"],
        searched={"Roborock S7": ["Roborock S7"]},
    )
    report = _assemble("| table |", "model", results)
    assert "No CVEs matched Roborock S7" in report
    assert "### Vulnerability table" in report
