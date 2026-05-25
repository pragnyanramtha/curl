#!/usr/bin/env python3
"""Regression tests for route-task.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROUTER = ROOT / "workforce" / "scripts" / "route-task.py"
ROUTE_CASES = ROOT / "workforce" / "evals" / "route-cases.json"
ROUTING_KEYWORDS = ROOT / "workforce" / "scripts" / "routing-keywords.json"
CASE_COUNTS = {"cli": 3, "primary": 422, "matched": 6, "not_matched": 11, "output_contains": 1, "json_routes": 2}
PRIMARY_OWNER_COUNTS = {"workforce-code-review": 295, "workforce-eng-manager": 12, "workforce-hr": 34, "workforce-orchestra": 7, "workforce-qa-release": 45, "workforce-research": 29}
CASE_SECTIONS, ROUTE_KEYS = set(CASE_COUNTS), {"primary", "also", "support", "confidence", "confidence_note"}
MAX_TOTAL_ROUTE_CASES = 450
FALSE_POSITIVE_GUARD_OWNERS = {"workforce-hr", "workforce-research", "workforce-code-review"}; ROUTE_OWNERS = {"workforce-orchestra", *json.loads(ROUTING_KEYWORDS.read_text())["route_order"]}
ROUTE_TIMEOUT_SECONDS = 15

ROUTER_SPEC = importlib.util.spec_from_file_location("workforce_route_task", ROUTER)
assert ROUTER_SPEC and ROUTER_SPEC.loader, f"could not load {ROUTER}"
ROUTER_MODULE = importlib.util.module_from_spec(ROUTER_SPEC)
ROUTER_SPEC.loader.exec_module(ROUTER_MODULE)


def route(task: str) -> str:
    routed = ROUTER_MODULE.route_task(task); route_owners = [routed.get("primary"), *routed.get("also", []), *routed.get("support", [])]; assert set(routed) == ROUTE_KEYS and set(route_owners) <= ROUTE_OWNERS and len(route_owners) == len(set(route_owners)) and routed.get("confidence") == 6 and "escalate to workforce-hr" in str(routed.get("confidence_note")), f"{task!r}: wrong route shape, owners, or confidence contract\n{routed}"
    lines = [f"primary: {routed['primary']}"]
    if routed["also"]:
        lines.append("also: " + ", ".join(routed["also"]))
    lines.append("support: " + ", ".join(routed["support"]))
    lines.append(f"confidence: {routed['confidence']}/10 {routed['confidence_note']}")
    return "\n".join(lines) + "\n"


def assert_cli(args: list[str], expected_returncode: int, expected_output: str) -> None:
    result = subprocess.run(
        [str(ROUTER), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=ROUTE_TIMEOUT_SECONDS,
    )
    assert result.returncode == expected_returncode and (not expected_returncode or not result.stdout), f"{args!r}: wrong return/stdout\n{result}"
    output = f"{result.stdout}{result.stderr}"
    if "--json" in args: parsed = json.loads(result.stdout); route_owners = [parsed.get("primary"), *parsed.get("also", []), *parsed.get("support", [])] if isinstance(parsed, dict) else []; assert isinstance(parsed, dict) and set(parsed) == ROUTE_KEYS and set(route_owners) <= ROUTE_OWNERS and len(route_owners) == len(set(route_owners)) and parsed.get("confidence") == 6 and "escalate to workforce-hr" in str(parsed.get("confidence_note")), f"{args!r}: wrong JSON object shape, owners, or confidence contract\n{output}"
    assert expected_output in output, f"{args!r}: missing {expected_output!r}\n{output}"


def assert_primary(task: str, expected: str) -> None:
    output = route(task)
    first = output.splitlines()[0]
    assert first == f"primary: {expected}", f"{task!r}: {first!r}\n{output}"


def assert_matched_owner(task: str, owner: str, expected: bool = True) -> None:
    output = route(task)
    matched_owners = {part.strip() for line in output.splitlines() if line.startswith(("primary: ", "also: ")) for part in line.split(": ", 1)[1].split(",")}
    assert matched_owners <= ROUTE_OWNERS and (owner in matched_owners) is expected, f"{task!r}: {'missing' if expected else 'unexpected'} matched owner {owner}\n{output}"


def assert_output_contains(task: str, expected: str) -> None:
    output = route(task); actual = next((line for line in output.splitlines() if line.startswith("support: ")), "") if expected.startswith("support: ") else ""
    assert ({part.strip() for part in actual.split(": ", 1)[1].split(",")} == {part.strip() for part in expected.split(": ", 1)[1].split(",")}) if expected.startswith("support: ") else expected in output, f"{task!r}: missing {expected!r} or support owners drifted\n{output}"


def assert_json_route(task: str, expected_primary: str, expected_also: set[str], expected_support: set[str]) -> None:
    route = ROUTER_MODULE.route_task(task); route_owners = [route.get("primary"), *route.get("also", []), *route.get("support", [])]
    assert set(route) == ROUTE_KEYS and route["primary"] == expected_primary and set(route_owners) <= ROUTE_OWNERS and len(route_owners) == len(set(route_owners)), f"{task!r}: wrong JSON shape, primary, owner set, or duplicate owner\n{route}"
    assert expected_also.issubset(set(route["also"])), f"{task!r}: missing JSON also entries\n{route}"
    assert expected_support.issubset(set(route["support"])), f"{task!r}: missing JSON support entries\n{route}"
    assert route["confidence"] == 6, f"{task!r}: unexpected JSON confidence\n{route}"
    assert "escalate to workforce-hr" in str(route["confidence_note"]), f"{task!r}: missing escalation note\n{route}"


def assert_owner(owner: object, owners: set[str], label: str) -> None:
    assert isinstance(owner, str) and owner in owners, f"{label}: invalid owner {owner!r}"


def validate_pair_cases(cases: object, owners: set[str], label: str, owner_required: bool = True) -> None:
    assert isinstance(cases, list), f"{label}: section must be a list"
    seen: set[tuple[str, str]] = set()
    for index, case in enumerate(cases):
        assert isinstance(case, list) and len(case) == 2, f"{label}[{index}]: expected [task, owner]"
        assert all(isinstance(value, str) for value in case), f"{label}[{index}]: values must be strings"
        assert all(value == value.strip() and value for value in case) and not any(owner in case[0].lower() for owner in owners), f"{label}[{index}]: values must be trimmed, non-empty, and non-tautological"
        key = (case[0], case[1])
        assert key not in seen, f"{label}[{index}]: duplicate case {case!r}"
        seen.add(key)
        if owner_required:
            assert_owner(case[1], owners, f"{label}[{index}]")


def validate_cases(cases: object) -> dict[str, object]:
    assert isinstance(cases, dict), "route cases must be an object"
    assert cases.get("version") == 1, "route cases version drifted"
    assert set(cases) == {"version", *CASE_SECTIONS}, f"route cases keys drifted: {sorted(cases)}"
    actual_counts = {section: len(cases[section]) for section in CASE_SECTIONS if isinstance(cases.get(section), list)}
    assert actual_counts == CASE_COUNTS, f"route case counts drifted: {actual_counts}"
    assert sum(actual_counts.values()) <= MAX_TOTAL_ROUTE_CASES, f"route case cap exceeded: {sum(actual_counts.values())} > {MAX_TOTAL_ROUTE_CASES}"

    owners = ROUTE_OWNERS
    assert isinstance(cases["cli"], list), "cli section must be a list"
    for index, case in enumerate(cases["cli"]):
        assert isinstance(case, dict), f"cli[{index}]: case must be an object"
        assert set(case) == {"args", "returncode", "contains"}, f"cli[{index}]: keys drifted"
        assert isinstance(case["args"], list) and all(isinstance(arg, str) for arg in case["args"]) and not any(owner in arg.lower() for arg in case["args"] for owner in owners), f"cli[{index}]: args must be non-tautological strings"
        assert isinstance(case["returncode"], int), f"cli[{index}]: returncode must be int"
        assert isinstance(case["contains"], str), f"cli[{index}]: contains must be string"

    for section in ("primary", "matched", "not_matched"):
        validate_pair_cases(cases[section], owners, section)
    primary_tasks = [task for task, _owner in cases["primary"]]
    normalized_primary_tasks = [" ".join("".join(char if char.isalnum() else " " for char in task.lower()).split()) for task in primary_tasks]
    assert len(primary_tasks) == len(set(primary_tasks)) and len(normalized_primary_tasks) == len(set(normalized_primary_tasks)), "primary section contains duplicate or punctuation-only duplicate tasks"
    primary_owners = {owner for _task, owner in cases["primary"]}; assert owners <= primary_owners, f"primary section missing owners: {sorted(owners - primary_owners)}"
    primary_owner_counts = {owner: sum(1 for _task, candidate in cases["primary"] if candidate == owner) for owner in owners}
    assert primary_owner_counts == PRIMARY_OWNER_COUNTS, f"primary owner counts drifted: {primary_owner_counts}"
    primary_cases, matched_cases = set(map(tuple, cases["primary"])), set(map(tuple, cases["matched"])); assert primary_cases.isdisjoint(matched_cases), f"matched duplicates primary route cases: {sorted(primary_cases & matched_cases)}"; positive_cases = primary_cases | matched_cases
    for index, case in enumerate(cases["not_matched"]):
        assert tuple(case) not in positive_cases, f"not_matched[{index}]: contradicts a positive route case {case!r}"
    not_matched_owners = {owner for _task, owner in cases["not_matched"]}
    assert FALSE_POSITIVE_GUARD_OWNERS <= not_matched_owners, f"not_matched missing false-positive guard owners: {sorted(FALSE_POSITIVE_GUARD_OWNERS - not_matched_owners)}"
    validate_pair_cases(cases["output_contains"], owners, "output_contains", owner_required=False)
    assert isinstance(cases["json_routes"], list), "json_routes section must be a list"
    for index, case in enumerate(cases["json_routes"]):
        assert isinstance(case, dict), f"json_routes[{index}]: case must be an object"
        assert set(case) == {"task", "primary", "also", "support"}, f"json_routes[{index}]: keys drifted"
        assert isinstance(case["task"], str) and case["task"].strip() and not any(owner in case["task"].lower() for owner in owners), f"json_routes[{index}]: task must be non-empty, non-tautological string"
        assert_owner(case["primary"], owners, f"json_routes[{index}].primary")
        for field in ("also", "support"):
            assert isinstance(case[field], list), f"json_routes[{index}].{field} must be a list"
            assert all(isinstance(owner, str) and owner.strip() for owner in case[field]), f"json_routes[{index}].{field} must contain non-empty strings"
        route_owners = [case["primary"], *case["also"], *case["support"]]
        assert len(route_owners) == len(set(route_owners)), f"json_routes[{index}]: duplicate owner across primary/also/support"
        for field in ("also", "support"):
            for owner in case[field]:
                assert_owner(owner, owners, f"json_routes[{index}].{field}")
    return cases


def main() -> int:
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]: print("usage: test-route-task.py"); return 0
    cases = validate_cases(json.loads(ROUTE_CASES.read_text()))

    for case in cases["cli"]:
        assert_cli(case["args"], case["returncode"], case["contains"])
    for task, expected in cases["primary"]:
        assert_primary(task, expected)
        if expected == "workforce-research" and "look up" in task.lower() and "docs" in task.lower():
            assert_matched_owner(task, "workforce-code-review", expected=False)
    for task, expected in cases["matched"]:
        assert_matched_owner(task, expected)
    for task, unexpected in cases["not_matched"]:
        assert_matched_owner(task, unexpected, expected=False)
    for task, expected in cases["output_contains"]:
        assert_output_contains(task, expected)
    for case in cases["json_routes"]:
        assert_json_route(case["task"], case["primary"], set(case["also"]), set(case["support"]))

    print("route-task tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
