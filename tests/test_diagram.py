"""Tests for the block diagram (systems_expert/diagram.py). No model, no network."""

from systems_expert.diagram import auto_edges, build_diagram, colour_key, style_key

SYSTEMS = ["Ring Camera", "Cisco RV340", "Windows 11 laptop"]


def test_style_key_known_and_unknown():
    assert style_key("IoT") == "iot"
    assert style_key("Networking") == "networking"
    assert style_key("Something new") == "other"  # no style of its own -> grey
    assert style_key(None) == "other"


def test_everything_links_to_the_networking_device():
    industry = {"Ring Camera": "IoT", "Cisco RV340": "Networking", "Windows 11 laptop": "Software"}
    # (i, j): system i is joined to system j. The hub is index 1.
    assert auto_edges(SYSTEMS, industry) == [(0, 1), (2, 1)]


def test_no_networking_device_means_no_links():
    industry = {"Ring Camera": "IoT", "Cisco RV340": "Hardware", "Windows 11 laptop": "Software"}
    assert auto_edges(SYSTEMS, industry) == []
    assert auto_edges(SYSTEMS, None) == []  # no labels at all


def test_extra_networking_devices_join_the_first():
    systems = ["Cisco RV340", "Netgear R7800", "Ring Camera"]
    industry = {"Cisco RV340": "Networking", "Netgear R7800": "Networking", "Ring Camera": "IoT"}
    assert auto_edges(systems, industry) == [(1, 0), (2, 0)]


def test_diagram_has_no_network_node():
    industry = {"Ring Camera": "IoT", "Cisco RV340": "Networking", "Windows 11 laptop": "Software"}
    text = build_diagram(SYSTEMS, industry)
    assert text.splitlines()[0] == "graph LR"
    assert "NET" not in text and "Network" not in text
    assert "S1 --- S2" in text and "S3 --- S2" in text


def test_diagram_colours_each_industry():
    industry = {"Ring Camera": "IoT", "Cisco RV340": "Networking", "Windows 11 laptop": "Software"}
    text = build_diagram(SYSTEMS, industry)
    assert "class S1 iot" in text
    assert "class S2 networking" in text
    assert "class S3 software" in text


def test_same_industry_shares_one_style_line():
    text = build_diagram(["A", "B"], {"A": "Software", "B": "Software"})
    assert "class S1,S2 software" in text
    assert text.count("classDef software") == 1


def test_unlabelled_system_is_grey_and_quotes_are_cleaned():
    text = build_diagram(['The "Best" Router'], None)
    assert "S1[\"The 'Best' Router\"]" in text
    assert "class S1 other" in text


def test_colour_key_lists_only_industries_in_use():
    key = colour_key(SYSTEMS, {"Ring Camera": "IoT", "Cisco RV340": "Networking"})
    assert "IoT" in key and "Networking" in key
    assert "Software" not in key
    assert colour_key(SYSTEMS, None) == ""
