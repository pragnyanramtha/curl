#!/usr/bin/env python3
"""Lightweight workforce router.

This is a heuristic helper, not a substitute for judgment. It gives the first
owner and support teams for a task so agents can start from a consistent map.
"""

from __future__ import annotations

import json
import re
import sys
from functools import lru_cache
from pathlib import Path


VERIFICATION_START_RE = re.compile(r"^\s*(check|test|verify|validate|qa)\b")
CODE_REVIEW_START_RE = re.compile(r"^\s*(audit|check|inspect|review)\b")
MULTI_AGENT_ORCHESTRA_RE = re.compile(
    r"\b(?:"
    r"subagents?|"
    r"spawn(?:\s+\w+){0,3}\s+agents?|"
    r"delegate(?:\s+\w+){0,3}\s+(?:parallel|agents?|work|task)|"
    r"one\s+agent\s+per|"
    r"agents?\s+in\s+parallel|"
    r"parallel\s+agents?"
    r")\b"
)
QA_BROWSER_EVIDENCE_KEYWORDS = (
    "browser console",
    "console errors",
    "network failures",
    "visual regression",
    "screenshot diff",
)
QA_ARTIFACT_VALIDATION_KEYWORDS = (
    "output artifact validation",
    "claim audit",
    "claimed evidence coverage",
)
AGENT_INSTRUCTION_REVIEW_KEYWORDS = (
    "agent instruction",
    "agents.md",
    "agent.md",
    "skill.md",
    "routing change",
    "tool access",
    "install policy",
    "safety boundary",
)
AGENT_INSTRUCTION_REVIEW_EXCLUSIONS = (
    "find",
    "scout",
    "public",
    "internet",
    "example",
    "license before install",
    "before install",
)
ROUTING_DATA = json.loads((Path(__file__).with_name("routing-keywords.json")).read_text())
BROAD_ORCHESTRA_KEYWORDS = ROUTING_DATA["broad_orchestra"]
ENGINEERING_ORCHESTRA_KEYWORDS = ROUTING_DATA["engineering_orchestra"]
ENGINEERING_MANAGER_REVIEW_KEYWORDS = ROUTING_DATA["engineering_manager_review"]
ENGINEERING_MANAGER_REVIEW_EXCLUSIONS = ROUTING_DATA["engineering_manager_review_exclusions"]
ROUTES = [(owner, ROUTING_DATA["routes"][owner]) for owner in ROUTING_DATA["route_order"]]

USAGE = "usage: route-task.py [--json] <task>"


@lru_cache(maxsize=None)
def keyword_pattern(keyword: str) -> re.Pattern[str]:
    """Match whole keywords/phrases so short terms like "pr" do not hit "prepare"."""
    normalized = re.escape(keyword).replace(r"\ ", r"\s+")
    forms = [normalized]
    if keyword.endswith("y"):
        forms.append(re.escape(f"{keyword[:-1]}ies").replace(r"\ ", r"\s+"))
    elif not keyword.endswith("s"):
        forms.append(f"{normalized}s")
    return re.compile(rf"(?<!\w)(?:{'|'.join(forms)})(?!\w)")


def contains_keyword(text: str, keyword: str) -> bool:
    return keyword_pattern(keyword).search(text) is not None


def expresses_low_confidence(text: str) -> bool:
    number = r"(\d+(?:\.\d+)?)"
    match = re.search(rf"\bconfidence\s*(?:is|:|=)?\s*{number}\s*(?:/|out\s+of)\s*10\b", text)
    if match and float(match.group(1)) < 7:
        return True
    match = re.search(rf"\bconfidence\s*(?:is|:|=)?\s*{number}\s*(?:%|percent)(?!\w)", text)
    if match and float(match.group(1)) < 70:
        return True
    match = re.search(rf"\bconfidence\s+(?:is\s+)?(?:below|under|less\s+than)\s+{number}\s*(?:%|percent)(?!\w)", text)
    if match and float(match.group(1)) <= 70:
        return True
    match = re.search(rf"\bconfidence\s+(?:is\s+)?(?:below|under|less\s+than)\s+{number}\s*(?:/|out\s+of)\s*10\b", text)
    if match and float(match.group(1)) <= 7:
        return True
    match = re.search(rf"\bconfidence\s+(?:is\s+)?(?:below|under|less\s+than)\s+{number}(?:\s*/\s*10)?\b", text)
    return bool(match and float(match.group(1)) <= 7)


def should_promote_engineering_manager(text: str) -> bool:
    if any(contains_keyword(text, keyword) for keyword in ENGINEERING_MANAGER_REVIEW_EXCLUSIONS):
        return False
    return any(contains_keyword(text, keyword) for keyword in ENGINEERING_MANAGER_REVIEW_KEYWORDS)


def should_promote_code_review(text: str, matches: list[str]) -> bool:
    return (
        "workforce-hr" not in matches
        and "workforce-code-review" in matches
        and CODE_REVIEW_START_RE.search(text) is not None
    )


def should_promote_agent_instruction_review(text: str, matches: list[str]) -> bool:
    return (
        "workforce-code-review" in matches
        and CODE_REVIEW_START_RE.search(text) is not None
        and any(contains_keyword(text, keyword) for keyword in AGENT_INSTRUCTION_REVIEW_KEYWORDS)
        and not any(contains_keyword(text, keyword) for keyword in AGENT_INSTRUCTION_REVIEW_EXCLUSIONS)
    )


def should_promote_qa_release(text: str, matches: list[str]) -> bool:
    return (
        "workforce-hr" not in matches
        and "workforce-qa-release" in matches
        and (
            any(contains_keyword(text, keyword) for keyword in QA_BROWSER_EVIDENCE_KEYWORDS)
            or (
                VERIFICATION_START_RE.search(text) is not None
                and any(contains_keyword(text, keyword) for keyword in QA_ARTIFACT_VALIDATION_KEYWORDS)
            )
        )
    )


def should_promote_orchestra(text: str) -> bool:
    return MULTI_AGENT_ORCHESTRA_RE.search(text) is not None


def route_task(task: str) -> dict[str, object]:
    lowered = task.lower()
    matches: list[str] = []
    for owner, keywords in ROUTES:
        if any(contains_keyword(lowered, keyword) for keyword in keywords):
            matches.append(owner)
    if should_promote_engineering_manager(lowered):
        matches = ["workforce-eng-manager", *[name for name in matches if name != "workforce-eng-manager"]]
    if should_promote_code_review(lowered, matches):
        matches = ["workforce-code-review", *[name for name in matches if name != "workforce-code-review"]]
    if should_promote_agent_instruction_review(lowered, matches):
        matches = ["workforce-code-review", *[name for name in matches if name != "workforce-code-review"]]
    if should_promote_qa_release(lowered, matches):
        matches = ["workforce-qa-release", *[name for name in matches if name != "workforce-qa-release"]]
    low_confidence = expresses_low_confidence(lowered)
    if low_confidence and "workforce-hr" not in matches:
        matches.insert(0, "workforce-hr")

    is_verification_request = VERIFICATION_START_RE.search(lowered) is not None
    is_broad = any(contains_keyword(lowered, keyword) for keyword in BROAD_ORCHESTRA_KEYWORDS) and not is_verification_request
    needs_engineering_lane = any(contains_keyword(lowered, keyword) for keyword in ENGINEERING_ORCHESTRA_KEYWORDS)
    if is_broad or should_promote_orchestra(lowered):
        if low_confidence:
            matches = [
                "workforce-hr",
                "workforce-orchestra",
                *[name for name in matches if name not in {"workforce-hr", "workforce-orchestra"}],
            ]
        else:
            matches = ["workforce-orchestra", *[name for name in matches if name != "workforce-orchestra"]]
        if needs_engineering_lane and "workforce-eng-manager" not in matches:
            matches.append("workforce-eng-manager")
    elif not matches:
        matches = ["workforce-orchestra"]

    support = [name for name, _ in ROUTES if name not in matches]
    return {
        "primary": matches[0],
        "also": matches[1:],
        "support": support[:3],
        "confidence": 6,
        "confidence_note": "heuristic; escalate to workforce-hr if risk is meaningful",
    }


def main() -> int:
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(USAGE)
        return 0

    json_output = "--json" in args
    if json_output:
        args = [arg for arg in args if arg != "--json"]

    task = " ".join(args).strip()
    if not task:
        print(USAGE, file=sys.stderr)
        return 2

    route = route_task(task)
    if json_output:
        print(json.dumps(route, sort_keys=True))
        return 0

    print(f"primary: {route['primary']}")
    also = route["also"]
    if isinstance(also, list) and also:
        print("also: " + ", ".join(str(name) for name in also))
    support = route["support"]
    if isinstance(support, list):
        print("support: " + ", ".join(str(name) for name in support))
    print(f"confidence: {route['confidence']}/10 {route['confidence_note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
