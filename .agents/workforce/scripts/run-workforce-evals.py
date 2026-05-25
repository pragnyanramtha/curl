#!/usr/bin/env python3
"""Run deterministic and optional Codex-backed workforce evaluations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[3]
WORKFORCE = WORKSPACE / ".agents" / "workforce"
SKILLS = WORKSPACE / ".agents" / "skills"
CONTRIBUTION_GATE = WORKFORCE / "contribution-gate.md"
ROUTING_KEYWORDS = WORKFORCE / "scripts" / "routing-keywords.json"
RESULTS = WORKFORCE / "evals" / "results"
DOCUMENT_ANCHORS = WORKFORCE / "evals" / "document-anchors.json"
SCENARIO = WORKFORCE / "evals" / "scenarios" / "broad-build-review-ship.md"
SCHEMA = WORKFORCE / "evals" / "workforce-eval.schema.json"
COMMITTED_CODEX_RESULT = RESULTS / "codex-broad-build-review-ship.json"
CODEX_RESULT = RESULTS / ".codex-broad-build-review-ship.latest.json"
TRUSTED_JSON_SURFACES = (ROUTING_KEYWORDS, DOCUMENT_ANCHORS, WORKFORCE / "evals" / "route-cases.json", SCHEMA, COMMITTED_CODEX_RESULT, WORKSPACE / "skills-lock.json")
CODEX_EVAL_ATTEMPTS = 2; EVAL_SCENARIO_REQUEST = "I need you to build a small feature, research any unknowns, review the code, and tell me if it is ready to ship"
WORKFORCE_SKILL_NAMES = "workforce-orchestra workforce-hr workforce-research workforce-eng-manager workforce-code-review workforce-qa-release"
REQUIRED_SKILLS = set(WORKFORCE_SKILL_NAMES.split())
REQUIRED_SUPPORT_SKILLS = {"skill-builder"}
SUPPORT_SKILL_FILES = {"skill-builder": set("SKILL.md scripts/scaffold.ts scripts/validate-skill.ts templates/SKILL.template.md templates/output-section.md templates/script.template.ts".split())}
ROUTER_ROUTE_OWNERS = "workforce-hr workforce-research workforce-code-review workforce-qa-release workforce-eng-manager".split()
REQUIRED_SKILL_SPECS = {
    "workforce-code-review": ("CR", "evaluative", "code-review"),
    "workforce-eng-manager": ("EM", "collaborative", "engineering"),
    "workforce-hr": ("HR", "collaborative", "staffing"),
    "workforce-orchestra": ("OR", "collaborative", "orchestration"),
    "workforce-qa-release": ("QA", "evaluative", "qa-release"),
    "workforce-research": ("RS", "evaluative", "research"),
}
REQUIRED_STATE_PREFIXES = {name: prefix for name, (prefix, _mode, _domain) in REQUIRED_SKILL_SPECS.items()}

MAX_WORKFORCE_SKILL_LINES = 1080
MAX_SINGLE_WORKFORCE_SKILL_LINES = 180
MAX_SKILL_DESCRIPTION_WORDS = 30
MAX_WORKFORCE_SKILL_DESCRIPTION_CHARS = 1400
MAX_AGENT_SHORT_DESCRIPTION_WORDS = 12
MIN_ANTI_PATTERNS = 3
MAX_CAPPED_FILE_BYTES = 65536
MAX_CAPPED_FILE_LINE_LENGTH = 2500
SKILLS_CLI_PACKAGE = "skills@1.5.7"
SKILL_BUILDER_HASH = "445b9262fa896a79dacace557eaf4ebaed21dea4615df31a85ae35e00f99cf88"
DANGEROUS_SHELL_SNIPPET = re.compile(r"\b(rm\s+-rf\s+[~/.$*]|git\s+(?:reset\s+--hard|checkout\s+--)|npm\s+audit\s+fix\s+--force|curl\b[^\n|]*\|\s*(?:sh|bash)|wget\b[^\n|]*\|\s*(?:sh|bash))")
HIDDEN_TEXT_SURFACE = re.compile(r"<!--|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|^\s*!`|^\s*```!", re.IGNORECASE | re.MULTILINE)
INSTRUCTION_OVERRIDE_SURFACE = re.compile(r"\b(?:ignore|disregard)\s+(?:all\s+|any\s+|previous\s+|above\s+)?instructions\b|\b(?:reveal|show)\s+(?:the\s+)?(?:system|developer)\s+prompt\b|\b(?:leak|exfiltrate)\s+(?:secrets|tokens|credentials)\b", re.IGNORECASE)
WORKFORCE_FILE_LINE_CAPS = {
    "charter.md": 90,
    "contribution-gate.md": 70,
    "escalation.md": 70,
    "release-decision-record.md": 60,
    "research.md": 60,
    "research-notes.md": 80,
    "review-board.md": 90,
    "routing.md": 100,
    "skill-risk.md": 50,
    "evals/results/codex-broad-build-review-ship.json": 5,
    "evals/scenarios/broad-build-review-ship.md": 32,
    "evals/workforce-eval.schema.json": 80,
    "scripts/agents-md-scout.sh": 60,
    "scripts/route-task.py": 250,
    "scripts/routing-keywords.json": 220,
    "scripts/test-route-task.py": 170,
    "scripts/run-workforce-evals.py": 609,
    "scripts/skill-scout.sh": 40,
    "evals/route-cases.json": 80,
    "evals/document-anchors.json": 260,
}
WORKSPACE_FILE_LINE_CAPS = {
    "README.md": 100,
    "CONTRIBUTING.md": 50,
    "AGENTS.md": 80,
    ".gitignore": 30,
    ".github/CODEOWNERS": 10,
    ".github/SECURITY.md": 20,
    ".github/pull_request_template.md": 40,
    ".github/dependabot.yml": 20,
    ".github/workflows/workforce-evals.yml": 60,
    "skills-lock.json": 30,
}
REQUIRED_SKILL_SECTIONS = "## Core Principle|## The States|## Diagnostic Process|## Key Questions|## Anti-Patterns|## Available Tools|## Example Interaction|## What You Do NOT Do|## Integration Graph".split("|")
REQUIRED_METADATA_KEYS = {"author", "version", "type", "mode", "domain"}
REQUIRED_FRONTMATTER_KEYS = {"name", "description", "license"}
REQUIRED_METADATA_VALUES = {"metadata.author": {"local-workforce"}, "metadata.version": {"1.0"}, "metadata.type": {"diagnostic"}, "metadata.mode": {"collaborative", "evaluative"}}
REQUIRED_SKILL_METADATA = {name: {"metadata.mode": mode, "metadata.domain": domain} for name, (_prefix, mode, domain) in REQUIRED_SKILL_SPECS.items()}
REQUIRED_AGENT_INTERFACE_KEYS = {"display_name", "short_description", "brand_color", "default_prompt"}; REQUIRED_AGENT_INTERFACES = {"workforce-orchestra": {"display_name": "Workforce Orchestra", "short_description": "Coordinate company-style AI teams", "brand_color": "#2563EB", "default_prompt": "Use $workforce-orchestra to coordinate this work across the right AI departments."}, "workforce-research": {"display_name": "Workforce Research", "short_description": "Research with sources and confidence", "brand_color": "#7C3AED", "default_prompt": "Use $workforce-research to produce a sourced brief before we act."}, "workforce-hr": {"display_name": "Workforce HR", "short_description": "Escalate and staff uncertain work", "brand_color": "#059669", "default_prompt": "Use $workforce-hr to route this low-confidence task and find the right skill or agent pattern."}, "workforce-eng-manager": {"display_name": "Engineering Manager", "short_description": "Plan fixes and execution lanes", "brand_color": "#0F766E", "default_prompt": "Use $workforce-eng-manager to plan this implementation or bug fix and assign engineering lanes."}, "workforce-qa-release": {"display_name": "QA Release", "short_description": "Validate behavior and release risk", "brand_color": "#EA580C", "default_prompt": "Use $workforce-qa-release to check acceptance, release readiness, and rollback risk."}, "workforce-code-review": {"display_name": "Code Review Board", "short_description": "Review code with specialist lenses", "brand_color": "#DC2626", "default_prompt": "Use $workforce-code-review to review this diff for real defects and missing tests."}}
REQUIRED_AGENT_POLICY_KEYS = {"allow_implicit_invocation"}
REQUIRED_DOCUMENT_ANCHOR_COUNTS = {
    path: int(count)
    for path, count in (entry.rsplit("=", 1) for entry in "workspace:AGENTS.md=16 workspace:README.md=23 workspace:.agents/workforce/charter.md=32 workspace:.agents/workforce/contribution-gate.md=19 workspace:CONTRIBUTING.md=5 workspace:.agents/workforce/routing.md=30 workspace:.agents/skills/workforce-qa-release/SKILL.md=16 workspace:.github/CODEOWNERS=1 workspace:.github/SECURITY.md=5 workspace:.github/pull_request_template.md=10 workspace:.agents/workforce/escalation.md=18 workspace:.agents/workforce/research.md=18 workspace:.agents/skills/workforce-research/SKILL.md=1 workspace:.agents/workforce/release-decision-record.md=22 workspace:.agents/skills/workforce-eng-manager/SKILL.md=6 workspace:.agents/workforce/review-board.md=52 workspace:.agents/skills/workforce-code-review/SKILL.md=25 workspace:.agents/workforce/skill-risk.md=28 workspace:.agents/workforce/scripts/skill-scout.sh=3 workspace:.agents/workforce/scripts/agents-md-scout.sh=4 workspace:.github/workflows/workforce-evals.yml=12 workspace:.github/dependabot.yml=5".split())
}
ANCHOR_ROOTS = {"workspace": WORKSPACE, "workforce": WORKFORCE, "skills": SKILLS}
def resolve_anchor_path(spec: str) -> Path:
    root_name, _, relative = spec.partition(":")
    if root_name not in ANCHOR_ROOTS or not relative:
        raise ValueError(f"bad document anchor path: {spec}")
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"document anchor path escapes allowed roots: {spec}")
    return ANCHOR_ROOTS[root_name] / relative_path

def document_anchor_checks() -> list[tuple[Path, str, list[str]]]:
    data = json.loads(DOCUMENT_ANCHORS.read_text())
    if data.get("version") != 1 or not isinstance(data.get("checks"), list):
        raise ValueError(f"bad document anchor file: {DOCUMENT_ANCHORS}")
    checks: list[tuple[Path, str, list[str]]] = []
    seen_paths: set[str] = set()
    anchor_counts: dict[str, int] = {}
    for index, entry in enumerate(data["checks"]):
        if not isinstance(entry, dict):
            raise ValueError(f"document anchor entry {index} must be an object")
        path_spec = entry.get("path")
        label = entry.get("label")
        anchors = entry.get("anchors")
        if not isinstance(path_spec, str) or not isinstance(label, str) or not isinstance(anchors, list):
            raise ValueError(f"document anchor entry {index} has invalid fields")
        if path_spec in seen_paths:
            raise ValueError(f"duplicate document anchor path: {path_spec}")
        seen_paths.add(path_spec)
        if not anchors:
            raise ValueError(f"{label} has no anchors")
        if any(not isinstance(anchor, str) or not anchor.strip() for anchor in anchors):
            raise ValueError(f"{label} has a blank or non-string anchor")
        if len(anchors) != len(set(anchors)):
            raise ValueError(f"{label} has duplicate anchors")
        anchor_counts[path_spec] = len(anchors)
        checks.append((resolve_anchor_path(path_spec), label, anchors))
    if anchor_counts != REQUIRED_DOCUMENT_ANCHOR_COUNTS:
        raise ValueError(f"document anchor counts drifted: {anchor_counts}")
    return checks

def run(cmd: list[str], *, input_text: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=WORKSPACE, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)

def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition: failures.append(message)
def require_git_ignored(path: str, failures: list[str]) -> None:
    require(run(["git", "check-ignore", "-q", path]).returncode == 0, f"path should be gitignored: {path}", failures)
def require_file_contains(path: Path, label: str, required_texts: list[str], failures: list[str]) -> None:
    require(path.exists(), f"missing {label}", failures)
    if not path.exists():
        return
    text = path.read_text()
    for required_text in required_texts:
        require(required_text in text, f"{label} does not mention {required_text}", failures)


def frontmatter(content: str) -> dict[str, str]:
    match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return {}
    values: dict[str, str] = {}; duplicates: set[str] = set(); in_metadata = False
    for line in match.group(1).splitlines():
        if line.startswith("metadata:"):
            in_metadata = True
            continue
        if in_metadata and line.startswith("  "):
            key, _, value = line.strip().partition(":")
            if key:
                scoped_key = f"metadata.{key}"; duplicates.add(scoped_key) if scoped_key in values else None; values[scoped_key] = value.strip().strip('"')
            continue
        in_metadata = False
        key, _, value = line.partition(":")
        if key:
            scoped_key = key.strip(); duplicates.add(scoped_key) if scoped_key in values else None; values[scoped_key] = value.strip().strip('"')
    if duplicates: values["__duplicate_keys__"] = ",".join(sorted(duplicates))
    return values


def validate_skill_files(name: str, skill: Path, meta: Path, failures: list[str]) -> None:
    skill_entries = {path.name for path in skill.parent.iterdir()}
    require(skill_entries == {"SKILL.md", "agents"}, f"unexpected skill files in {skill.parent}: {sorted(skill_entries)}", failures)
    content = skill.read_text()
    require(not re.search(r"[\u200b-\u200f\u202a-\u202e\U000e0000-\U000e007f]|<!--|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|^\s*!`|^\s*```!", content, re.IGNORECASE | re.MULTILINE), f"hidden instruction surface in {skill}", failures)
    require(len(fence_langs := re.findall(r"^```([A-Za-z0-9_-]*)", content, re.MULTILINE)) % 2 == 0 and set(fence_langs) <= {"", "bash", "text"}, f"unsupported or unbalanced code fences in {skill}: {fence_langs}", failures)
    fm = frontmatter(content)
    require(bool(fm), f"missing frontmatter: {skill}", failures)
    require("__duplicate_keys__" not in fm, f"duplicate frontmatter keys in {skill}: {fm.get('__duplicate_keys__')}", failures)
    top_level_keys = {key for key in fm if not key.startswith(("metadata.", "__"))}; metadata_keys = {key.removeprefix("metadata.") for key in fm if key.startswith("metadata.")}
    require(top_level_keys == REQUIRED_FRONTMATTER_KEYS, f"frontmatter keys drifted in {skill}: {sorted(top_level_keys)}", failures)
    require(metadata_keys == REQUIRED_METADATA_KEYS, f"metadata keys drifted in {skill}: {sorted(metadata_keys)}", failures)
    require(fm.get("name") == name, f"skill name mismatch in {skill}: {fm.get('name')}", failures)
    require(bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", name)) and "--" not in name, f"invalid skill name: {name}", failures)
    description = fm.get("description", "")
    desc_words = len(description.split())
    require(len(description) <= 1024, f"description too long in {skill}", failures)
    require(desc_words <= MAX_SKILL_DESCRIPTION_WORDS, f"description word count too high in {skill}: {desc_words} > {MAX_SKILL_DESCRIPTION_WORDS}", failures)
    require(len(re.findall(r'"[^"]+"|`[^`]+`', description)) < 5 and sum(1 for segment in description.split(",") if len(segment.strip().split()) <= 3) < 8, f"description looks trigger-stuffed in {skill}", failures)
    require(bool(re.search(r"\b(Use when|Use for|when|before|after)\b", description)), f"description missing trigger cue in {skill}", failures)
    require(fm.get("license") == "MIT", f"missing MIT license in {skill}", failures)
    for key, allowed in REQUIRED_METADATA_VALUES.items():
        require(fm.get(key) in allowed, f"invalid {key} in {skill}: {fm.get(key)}", failures)
    require(bool(re.fullmatch(r"[a-z][a-z-]*", fm.get("metadata.domain", ""))), f"invalid metadata.domain in {skill}", failures)
    for key, expected_value in REQUIRED_SKILL_METADATA[name].items():
        require(fm.get(key) == expected_value, f"{key} drifted in {skill}: {fm.get(key)}", failures)
    skill_refs = set(re.findall(r"\bworkforce-[a-z-]+\b", content))
    unknown_skill_refs = sorted(skill_refs - REQUIRED_SKILLS)
    require(not unknown_skill_refs, f"unknown workforce skill reference in {skill}: {unknown_skill_refs}", failures)
    for section in REQUIRED_SKILL_SECTIONS:
        require(section in content, f"missing section {section} in {skill}", failures)
    anti_pattern_section = re.search(r"## Anti-Patterns.*?(?=\n## |\Z)", content, re.DOTALL)
    anti_pattern_count = len(re.findall(r"^### ", anti_pattern_section.group(0), re.MULTILINE)) if anti_pattern_section else 0
    require(anti_pattern_count >= MIN_ANTI_PATTERNS, f"not enough anti-patterns in {skill}: {anti_pattern_count}", failures)
    state_ids = re.findall(r"^### State ([A-Z]{2}\d+):", content, re.MULTILINE); state_prefixes = [state_id[:2] for state_id in state_ids]
    state_blocks = re.findall(r"^### State [A-Z]{2}\d+:.*?(?=^### State |\n## |\Z)", content, re.MULTILINE | re.DOTALL)
    require(3 <= len(state_prefixes) <= 7, f"expected 3-7 diagnostic states in {skill}", failures); require(len(state_ids) == len(set(state_ids)), f"duplicate diagnostic state id in {skill}: {state_ids}", failures)
    require(len(state_blocks) == len(state_prefixes), f"could not parse all diagnostic states in {skill}", failures)
    expected_prefix = REQUIRED_STATE_PREFIXES[name]
    require(
        all(prefix == expected_prefix for prefix in state_prefixes),
        f"state prefix mismatch in {skill}: expected {expected_prefix}, found {state_prefixes}",
        failures,
    )
    for block in state_blocks:
        state_title = block.splitlines()[0].removeprefix("### ")
        for component in ("**Symptoms:**", "**Key Questions:**", "**Interventions:**"):
            require(component in block, f"missing {component} in {skill} {state_title}", failures)

    agent_entries = {path.name for path in meta.parent.iterdir()}
    require(agent_entries == {"openai.yaml"}, f"unexpected agent metadata entries in {meta.parent}: {sorted(agent_entries)}", failures)
    meta_text = meta.read_text()
    require(all(ord(char) < 128 for char in meta_text) and not HIDDEN_TEXT_SURFACE.search(meta_text) and not INSTRUCTION_OVERRIDE_SURFACE.search(meta_text), f"hidden or overriding instruction surface in {meta}", failures)
    top_level_keys: set[str] = set(); seen_agent_keys: set[str] = set(); duplicate_agent_keys: set[str] = set()
    block_keys = {"interface": set[str](), "policy": set[str]()}
    current_block = ""
    for line in meta_text.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            key, _, value = line.partition(":")
            scoped_key = key.strip(); duplicate_agent_keys.add(scoped_key) if scoped_key in seen_agent_keys else None; seen_agent_keys.add(scoped_key); top_level_keys.add(scoped_key)
            current_block = scoped_key if not value.strip() else ""
        elif current_block in block_keys:
            key, _, _value = line.strip().partition(":"); scoped_key = f"{current_block}.{key}"; duplicate_agent_keys.add(scoped_key) if scoped_key in seen_agent_keys else None; seen_agent_keys.add(scoped_key)
            block_keys[current_block].add(key)
    require(not duplicate_agent_keys, f"duplicate agent metadata keys in {meta}: {sorted(duplicate_agent_keys)}", failures); require(top_level_keys == {"interface", "policy"}, f"agent metadata top-level keys drifted in {meta}: {sorted(top_level_keys)}", failures)
    require(block_keys["interface"] == REQUIRED_AGENT_INTERFACE_KEYS, f"agent interface keys drifted in {meta}: {sorted(block_keys['interface'])}", failures)
    require(block_keys["policy"] == REQUIRED_AGENT_POLICY_KEYS, f"agent policy keys drifted in {meta}: {sorted(block_keys['policy'])}", failures); require(not (meta_refs := set(re.findall(r"\$?(workforce-[a-z-]+)", meta_text)) - REQUIRED_SKILLS), f"unknown workforce skill reference in {meta}: {sorted(meta_refs)}", failures)
    interface_values = {key: value for key, value in re.findall(r'^\s*(display_name|short_description|brand_color|default_prompt):\s+"([^"]+)"', meta_text, re.MULTILINE)}; require(interface_values == REQUIRED_AGENT_INTERFACES[name], f"agent interface values drifted in {meta}: {interface_values}", failures); short_description = re.search(r'^\s*short_description:\s+"([^"]+)"', meta_text, re.MULTILINE)
    require(bool(short_description), f"missing quoted short_description in {meta}", failures)
    if short_description:
        short_description_words = len(short_description.group(1).split())
        require(short_description_words <= MAX_AGENT_SHORT_DESCRIPTION_WORDS, f"short_description word count too high in {meta}: {short_description_words} > {MAX_AGENT_SHORT_DESCRIPTION_WORDS}", failures)
    require(bool(re.search(r'brand_color:\s+"#[0-9A-Fa-f]{6}"', meta_text)), f"missing valid brand_color in {meta}", failures)
    require(f"$${name}" not in meta_text, f"bad escaped default_prompt in {meta}", failures)
    require(f"${name}" in meta_text, f"default_prompt must mention ${name} in {meta}", failures)
    require("allow_implicit_invocation: true" in meta_text, f"implicit invocation disabled in {meta}", failures)

def validate_scout_script_usage(script_name: str, expected_usage: str, failures: list[str]) -> None:
    result = run([str(WORKFORCE / "scripts" / script_name)]); help_result = run([str(WORKFORCE / "scripts" / script_name), "--help"])
    output = f"{result.stdout}{result.stderr}"; help_output = f"{help_result.stdout}{help_result.stderr}"
    script_text = (WORKFORCE / "scripts" / script_name).read_text()
    require("NETWORK:" in script_text, f"{script_name} should disclose network use", failures)
    require("SCOUT_TIMEOUT_SECONDS" in script_text and "timeout " in script_text, f"{script_name} should bound network calls with a timeout", failures)
    for timeout_value in ("0", "999999"):
        bad_timeout = run(["env", f"SCOUT_TIMEOUT_SECONDS={timeout_value}", str(WORKFORCE / "scripts" / script_name), "safe-query"]); require(bad_timeout.returncode == 2 and "SCOUT_TIMEOUT_SECONDS" in f"{bad_timeout.stdout}{bad_timeout.stderr}", f"{script_name} should reject unsafe timeout {timeout_value}", failures)
    if script_name == "skill-scout.sh":
        require(f"SKILLS_CLI_PACKAGE:-{SKILLS_CLI_PACKAGE}" in script_text, f"{script_name} default Skills CLI package drifted", failures)
        bad_package = run(["env", "SKILLS_CLI_PACKAGE=--version", str(WORKFORCE / "scripts" / script_name), "safe-query"]); require(bad_package.returncode == 2 and "skills@<semver>" in f"{bad_package.stdout}{bad_package.stderr}", f"{script_name} should reject unsafe Skills CLI package overrides", failures)
    if script_name == "agents-md-scout.sh":
        require("filename:AGENTS.md" in script_text and " -- " in script_text, f"{script_name} should pass hyphen-safe gh search queries", failures)
    require(result.returncode == 2, f"{script_name} should exit 2 without a query", failures)
    require(expected_usage in output, f"{script_name} should print usage without a query", failures)
    require(help_result.returncode == 0 and expected_usage in help_output and "NETWORK:" not in help_output, f"{script_name} --help should print usage without network disclosure", failures)
    for token in ("sk-" + ("a" * 24), "gho_" + ("a" * 24), "github_pat_" + ("a" * 24), "AKIA" + ("A" * 16), "xoxb-" + ("a" * 24), "AIza" + ("A" * 35), "BEGIN RSA PRIVATE KEY"):
        blocked = run([str(WORKFORCE / "scripts" / script_name), token])
        require(blocked.returncode == 2 and "refusing" in f"{blocked.stdout}{blocked.stderr}", f"{script_name} should refuse secret-looking queries", failures)


def validate_readme(failures: list[str]) -> None:
    readme = (WORKSPACE / "README.md").read_text()
    for name in sorted(REQUIRED_SKILLS | REQUIRED_SUPPORT_SKILLS):
        require(name in readme, f"README does not mention {name}", failures)


def validate_document_anchors(failures: list[str]) -> None:
    try:
        checks = document_anchor_checks()
    except Exception as exc:  # noqa: BLE001
        failures.append(f"could not load document anchors: {exc}")
        return
    for path, label, required_texts in checks:
        require_file_contains(path, label, required_texts, failures)

def validate_file_line_caps(failures: list[str]) -> None:
    tracked_workforce = run(["git", "ls-files", ".agents/workforce"])
    require(tracked_workforce.returncode == 0, "could not list tracked workforce files", failures)
    if tracked_workforce.returncode == 0:
        tracked_files = {path.removeprefix(".agents/workforce/") for path in tracked_workforce.stdout.splitlines()}
        require(tracked_files == set(WORKFORCE_FILE_LINE_CAPS), f"tracked workforce file caps drifted: {sorted(tracked_files ^ set(WORKFORCE_FILE_LINE_CAPS))}", failures)
    tracked_github = run(["git", "ls-files", ".github"])
    require(tracked_github.returncode == 0, "could not list tracked GitHub files", failures)
    if tracked_github.returncode == 0:
        expected_github = {path for path in WORKSPACE_FILE_LINE_CAPS if path.startswith(".github/")}
        tracked_files = set(tracked_github.stdout.splitlines())
        require(tracked_files == expected_github, f"tracked GitHub file caps drifted: {sorted(tracked_files ^ expected_github)}", failures)
    for root, line_caps in ((WORKFORCE, WORKFORCE_FILE_LINE_CAPS), (WORKSPACE, WORKSPACE_FILE_LINE_CAPS)):
        for relative_path, max_lines in line_caps.items():
            path = root / relative_path
            require(path.exists(), f"missing file with line cap: {path}", failures)
            if path.exists():
                lines = path.read_text().splitlines()
                require(len(lines) <= max_lines, f"{relative_path} is too large: {len(lines)} lines > {max_lines}", failures)
                byte_count = len(path.read_bytes())
                require(byte_count <= MAX_CAPPED_FILE_BYTES, f"{relative_path} is too large: {byte_count} bytes > {MAX_CAPPED_FILE_BYTES}", failures)
                longest = max(map(len, lines), default=0)
                require(longest <= MAX_CAPPED_FILE_LINE_LENGTH, f"{relative_path} has a too-long line: {longest} > {MAX_CAPPED_FILE_LINE_LENGTH}", failures)


def validate_routing_keywords(failures: list[str]) -> None:
    try:
        data = json.loads(ROUTING_KEYWORDS.read_text())
    except Exception as exc:  # noqa: BLE001
        failures.append(f"could not parse {ROUTING_KEYWORDS}: {exc}")
        return
    required_keys = {"broad_orchestra", "engineering_orchestra", "engineering_manager_review", "engineering_manager_review_exclusions", "route_order", "routes"}
    require(set(data) == required_keys, f"routing keyword keys drifted: {sorted(data)}", failures)
    require(data.get("route_order") == ROUTER_ROUTE_OWNERS, "routing keyword owner order drifted", failures)
    keyword_list_keys = ("broad_orchestra", "engineering_orchestra", "engineering_manager_review", "engineering_manager_review_exclusions")
    for key in keyword_list_keys:
        require(isinstance(data.get(key), list) and bool(data[key]), f"missing routing keyword list: {key}", failures)
    routes = data.get("routes")
    require(isinstance(routes, dict), "routing keywords routes must be an object", failures)
    if not isinstance(routes, dict):
        return
    require(set(routes) == set(ROUTER_ROUTE_OWNERS), f"routing keyword owner set drifted: {sorted(routes)}", failures)
    keyword_groups = {key: data.get(key, []) for key in keyword_list_keys}
    keyword_groups.update(routes)
    for label, keywords in keyword_groups.items():
        if not isinstance(keywords, list):
            continue
        require(all(isinstance(keyword, str) and keyword == keyword.strip().lower() and keyword for keyword in keywords), f"bad routing keyword in {label}", failures)
        require(len(keywords) == len(set(keywords)), f"duplicate routing keyword in {label}", failures)
    seen_route_keywords: dict[str, str] = {}
    for owner in ROUTER_ROUTE_OWNERS:
        require(isinstance(routes.get(owner), list) and bool(routes[owner]), f"missing route keywords for {owner}", failures)
        for keyword in routes.get(owner, []):
            previous = seen_route_keywords.get(keyword)
            require(previous is None, f"routing keyword {keyword!r} appears in both {previous} and {owner}", failures)
            seen_route_keywords[keyword] = owner


def validate_skills_lock(failures: list[str]) -> None:
    lockfile = WORKSPACE / "skills-lock.json"
    require(lockfile.exists(), "missing skills-lock.json", failures)
    tracked = run(["git", "ls-files", "--error-unmatch", "skills-lock.json"])
    require(tracked.returncode == 0, "skills-lock.json is not tracked by git", failures)
    if not lockfile.exists():
        return

    try:
        data = json.loads(lockfile.read_text())
    except Exception as exc:  # noqa: BLE001
        failures.append(f"could not parse skills-lock.json: {exc}")
        return

    skills = data.get("skills", {})
    require(set(data) == {"version", "skills"}, f"skills-lock.json keys drifted: {sorted(data)}", failures)
    require(data.get("version") == 1, "skills-lock.json version must be 1", failures)
    require(set(skills) == REQUIRED_SUPPORT_SKILLS, f"skills-lock.json should only lock support skills: {sorted(skills)}", failures)
    skill_builder = skills.get("skill-builder", {})
    require(set(skill_builder) == {"source", "sourceType", "skillPath", "computedHash"}, f"skill-builder lock keys drifted: {sorted(skill_builder)}", failures)
    require(skill_builder.get("source") == "jwynia/agent-skills", "skill-builder lock source drifted", failures)
    require(skill_builder.get("sourceType") == "github", "skill-builder lock sourceType drifted", failures)
    require(skill_builder.get("skillPath") == "skills/general/meta/skill-builder/SKILL.md", "skill-builder lock skillPath drifted", failures)
    computed_hash = str(skill_builder.get("computedHash", ""))
    require(computed_hash == SKILL_BUILDER_HASH, "skill-builder lock hash drifted", failures)


def validate_skill_inventory(failures: list[str]) -> None:
    expected = REQUIRED_SKILLS | REQUIRED_SUPPORT_SKILLS
    require(all(path.is_dir() for path in SKILLS.iterdir()), "project skill inventory contains top-level files", failures)
    skill_dirs = {path.name for path in SKILLS.iterdir() if path.is_dir()}
    require(skill_dirs == expected, f"project skill inventory drifted: {sorted(skill_dirs)}", failures)
    require(set(SUPPORT_SKILL_FILES) == REQUIRED_SUPPORT_SKILLS, "support skill file map drifted", failures)
    for name, expected_files in SUPPORT_SKILL_FILES.items():
        skill_root = SKILLS / name
        actual_files = {path.relative_to(skill_root).as_posix() for path in skill_root.rglob("*") if path.is_file()}
        require(actual_files == expected_files, f"{name} support skill files drifted: {sorted(actual_files)}", failures)
        hasher = hashlib.sha256()
        for relative_path in sorted(actual_files): hasher.update(relative_path.encode()); hasher.update((skill_root / relative_path).read_bytes())
        require(name != "skill-builder" or hasher.hexdigest() == SKILL_BUILDER_HASH, f"{name} support skill content hash drifted", failures)

def validate_eval_result_data(data: object, label: str, failures: list[str]) -> None:
    if not isinstance(data, dict): failures.append(f"{label} must be a JSON object"); return

    required_keys = {"pass", "primary_owner", "staffed_roles", "escalation_works", "release_decision", "evidence", "issues", "recommendations"}
    require(set(data) == required_keys, f"{label} keys drifted: {sorted(data)}", failures)
    require(isinstance(data.get("pass"), bool), f"{label} pass must be boolean", failures)
    require(isinstance(data.get("primary_owner"), str), f"{label} primary_owner must be string", failures)
    require(isinstance(data.get("escalation_works"), bool), f"{label} escalation_works must be boolean", failures)
    require(data.get("release_decision") in {"ship", "no-ship", "not-applicable"}, f"{label} release_decision is invalid", failures)

    for key in ("staffed_roles", "evidence", "issues", "recommendations"):
        values = data.get(key)
        require(isinstance(values, list), f"{label} {key} must be a list", failures)
        if isinstance(values, list):
            require(all(isinstance(value, str) and value.strip() for value in values), f"{label} {key} must contain nonblank strings", failures)

    staffed = set(data.get("staffed_roles", [])) if isinstance(data.get("staffed_roles"), list) else set(); require(not isinstance(data.get("staffed_roles"), list) or len(data["staffed_roles"]) == len(staffed), f"{label} staffed_roles must be unique", failures); require(staffed <= REQUIRED_SKILLS, f"{label} staffed_roles contains unknown roles: {sorted(staffed - REQUIRED_SKILLS)}", failures)
    evidence = data.get("evidence", [])
    issues = data.get("issues", [])
    recommendations = data.get("recommendations", [])
    evidence_text = " ".join(evidence).lower() if isinstance(evidence, list) and all(isinstance(value, str) for value in evidence) else ""
    require(data.get("primary_owner") == "workforce-orchestra", f"{label} selected wrong primary owner: {data.get('primary_owner')}", failures)
    require(REQUIRED_SKILLS.issubset(staffed), f"{label} did not staff all expected roles: {sorted(staffed)}", failures)
    require(data.get("escalation_works") is True, f"{label} says escalation does not work", failures)
    require(data.get("release_decision") != "ship", f"{label} should not ship a read-only scenario with no artifact", failures)
    require(isinstance(evidence, list) and bool(evidence), f"{label} must include evidence", failures)
    require("ai eval was skipped" not in evidence_text and "--ai was not requested" not in evidence_text, f"{label} includes stale skipped-AI evidence", failures)
    require(isinstance(recommendations, list) and bool(recommendations), f"{label} must include recommendations", failures)
    if data.get("pass"):
        require(data.get("release_decision") == "not-applicable", f"{label} should use not-applicable release decision when passing", failures)
        require(issues == [], f"{label} pass should not include issues", failures)


def validate_committed_eval_results(failures: list[str]) -> None:
    require(COMMITTED_CODEX_RESULT.exists(), f"missing committed eval result: {COMMITTED_CODEX_RESULT}", failures)
    if not COMMITTED_CODEX_RESULT.exists():
        return
    try:
        data = json.loads(COMMITTED_CODEX_RESULT.read_text())
    except Exception as exc:  # noqa: BLE001
        failures.append(f"could not parse committed eval result: {exc}")
        return
    validate_eval_result_data(data, "committed Codex eval result", failures)
def validate_trusted_json_surfaces(failures: list[str]) -> None:
    for path in TRUSTED_JSON_SURFACES:
        text = path.read_text() if path.exists() else ""; require(not text or (all(ord(char) < 128 for char in text) and not HIDDEN_TEXT_SURFACE.search(text) and not INSTRUCTION_OVERRIDE_SURFACE.search(text)), f"hidden or overriding instruction surface in trusted JSON data: {path}", failures)
        try: json.loads(text, object_pairs_hook=lambda pairs: (_ for _ in ()).throw(ValueError(f"duplicate keys: {sorted({key for key, _value in pairs if sum(1 for candidate, _candidate_value in pairs if candidate == key) > 1})}")) if len({key for key, _value in pairs}) != len(pairs) else dict(pairs)) if text else None
        except Exception as exc: failures.append(f"could not parse trusted JSON data without duplicate keys: {path}: {exc}")

def is_transient_codex_schema_dead_end(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    notes = " ".join(str(note) for key in ("issues", "recommendations") if isinstance(data.get(key), list) for note in data.get(key, []))
    lowered = notes.lower()
    return (
        data.get("primary_owner") == ""
        and data.get("staffed_roles") == []
        and data.get("evidence") == []
        and ("schema" in lowered or "structured" in lowered)
        and ("tool" in lowered or "inspect" in lowered)
    )

def deterministic_checks() -> list[str]:
    failures: list[str] = []

    require(CONTRIBUTION_GATE.exists(), "missing contribution gate", failures)
    require((WORKSPACE / "LICENSE").exists(), "missing repo LICENSE for MIT skill licenses", failures)
    require(set(REQUIRED_STATE_PREFIXES) == REQUIRED_SKILLS, "state prefix map drifted", failures)
    require(set(REQUIRED_SKILL_METADATA) == REQUIRED_SKILLS, "skill metadata map drifted", failures)
    for path in (item for root in (SKILLS, WORKFORCE) for item in root.rglob("*")):
        artifact_path = path.relative_to(WORKSPACE).as_posix()
        require(all(ord(char) < 128 for char in artifact_path) and not HIDDEN_TEXT_SURFACE.search(artifact_path) and not INSTRUCTION_OVERRIDE_SURFACE.search(artifact_path), f"suspicious workforce artifact path: {artifact_path}", failures)
        require(not path.is_symlink(), f"symlink not allowed in workforce artifacts: {path}", failures)
    validate_readme(failures)
    validate_document_anchors(failures)
    validate_file_line_caps(failures)
    workflow = (WORKSPACE / ".github" / "workflows" / "workforce-evals.yml").read_text(); require("pull_request_target:" not in workflow and "workflow_run:" not in workflow and "concurrency:" in workflow and "cancel-in-progress: true" in workflow and not re.search(r":\s*write\b", workflow) and not re.search(r"(?ms)^(?P<i>\s*)(?:run|script):\s*(?:[^\n]*\$\{\{|\|\n(?:(?P=i)  .*\n)*?(?P=i)  .*\$\{\{)", workflow), "workflow should avoid privileged PR triggers, write permissions, run/script expression interpolation, and uncanceled stale CI", failures)
    for action_ref in re.findall(r"(?m)^\s*-\s+uses:\s+([^#\s]+)", workflow): require(action_ref.startswith("./") or bool(re.search(r"@[0-9a-f]{40}$", action_ref)), f"workflow action should be pinned to full SHA: {action_ref}", failures)
    validate_routing_keywords(failures); validate_trusted_json_surfaces(failures)
    validate_skills_lock(failures)
    validate_skill_inventory(failures)
    validate_committed_eval_results(failures); require('"uniqueItems"' not in SCHEMA.read_text(), "Codex output schema must keep uniqueness checks in the validator; uniqueItems is unsupported", failures)
    agents = (WORKSPACE / "AGENTS.md").read_text(); scenario_text = SCENARIO.read_text(); require(0 <= agents.find("## Company-Style Skill Routing") < agents.find("## HR Discovery") < agents.find("## Workforce Testing") and all(name in agents for name in REQUIRED_SKILLS), "AGENTS.md should keep mandatory workforce routing before discovery and testing", failures); require_file_contains(SCENARIO, "Codex eval scenario", ["Expected output:", "Return a concise JSON result"], failures); require(EVAL_SCENARIO_REQUEST in scenario_text and EVAL_SCENARIO_REQUEST in (WORKFORCE / "evals" / "route-cases.json").read_text(), "Codex eval scenario request should match deterministic route cases", failures); require(not (scenario_refs := sorted(REQUIRED_SKILLS & set(re.findall(r"\bworkforce-[a-z-]+\b", scenario_text)))), f"Codex eval scenario leaks expected skill ids: {scenario_refs}", failures)
    for ignored_path in (".reference/gstack/", ".agents/workforce/scripts/__pycache__/", ".agents/workforce/evals/results/.codex-broad-build-review-ship.latest.json"):
        require_git_ignored(ignored_path, failures)
    md_paths = [WORKSPACE / p for p in WORKSPACE_FILE_LINE_CAPS if p.endswith(".md")] + [WORKFORCE / p for p in WORKFORCE_FILE_LINE_CAPS if p.endswith(".md")] + [SKILLS / name / "SKILL.md" for name in REQUIRED_SKILLS]
    md_text = ""
    for path in md_paths:
        text = path.read_text()
        md_text += text
        require(all(ord(char) < 128 for char in text), f"non-ASCII text in {path}", failures)
        require(not HIDDEN_TEXT_SURFACE.search(text), f"hidden instruction surface in {path}", failures)
        require(not INSTRUCTION_OVERRIDE_SURFACE.search(text), f"instruction-override phrase in trusted docs: {path}", failures)
        for ref in re.findall(r"(?m)^\s*(?:bash\s+)?(\.agents/workforce/scripts/[A-Za-z0-9_.-]+)", text):
            require((WORKSPACE / ref).is_file() and os.access(WORKSPACE / ref, os.X_OK), f"bad script command reference in {path}: {ref}", failures)
        for ref in re.findall(r"\[[^\]]+\]\((?![a-z]+:|#)([^)#]+)", text):
            target = (path.parent / ref.strip("<>")).resolve(strict=False)
            require(target == WORKSPACE.resolve() or target.is_relative_to(WORKSPACE.resolve()), f"markdown link escapes workspace in {path}: {ref}", failures)
            require(target.is_file(), f"broken markdown link in {path}: {ref}", failures)
        for fence in ("```", "~~~"):
            require(len(re.findall(rf"^{re.escape(fence)}", text, re.MULTILINE)) % 2 == 0, f"unclosed markdown fence {fence} in {path}", failures)
        require(not DANGEROUS_SHELL_SNIPPET.search(text), f"dangerous shell snippet in {path}", failures)

    descriptions = [frontmatter((SKILLS / name / "SKILL.md").read_text()).get("description", "") for name in REQUIRED_SKILLS]
    require((description_chars := sum(map(len, descriptions))) <= MAX_WORKFORCE_SKILL_DESCRIPTION_CHARS, f"workforce skill descriptions too long: {description_chars} > {MAX_WORKFORCE_SKILL_DESCRIPTION_CHARS}", failures)
    require(len(set(descriptions)) == len(descriptions), f"duplicate skill descriptions: {descriptions}", failures)
    require(len({description.split(maxsplit=1)[0].lower() for description in descriptions}) == len(descriptions), f"skill description action verbs overlap: {descriptions}", failures)

    for name in REQUIRED_SKILLS:
        skill = SKILLS / name / "SKILL.md"
        meta = SKILLS / name / "agents" / "openai.yaml"
        require(skill.exists(), f"missing {skill}", failures)
        require(meta.exists(), f"missing {meta}", failures)
        if skill.exists() and meta.exists():
            validate_skill_files(name, skill, meta, failures)
        for ref in re.findall(r"`(\.agents/[^`]+\.md)`", skill.read_text() if skill.exists() else ""):
            require((WORKSPACE / ref).exists(), f"broken skill reference in {skill}: {ref}", failures)

    skill_line_counts = {name: len((SKILLS / name / "SKILL.md").read_text().splitlines()) for name in REQUIRED_SKILLS}
    for name, skill_lines in skill_line_counts.items():
        require(skill_lines <= MAX_SINGLE_WORKFORCE_SKILL_LINES, f"{name} skill is too large: {skill_lines} lines > {MAX_SINGLE_WORKFORCE_SKILL_LINES}", failures)
    require((total_skill_lines := sum(skill_line_counts.values())) <= MAX_WORKFORCE_SKILL_LINES, f"workforce skills are too large: {total_skill_lines} lines > {MAX_WORKFORCE_SKILL_LINES}", failures)

    route_tests = run([str(WORKFORCE / "scripts" / "test-route-task.py")]); route_test_help = run([str(WORKFORCE / "scripts" / "test-route-task.py"), "--help"])
    require(route_tests.returncode == 0, f"route tests failed: {route_tests.stdout}{route_tests.stderr}", failures); require(route_test_help.returncode == 0 and "usage:" in route_test_help.stdout and "route-task tests passed" not in route_test_help.stdout, "test-route-task.py --help should print usage without running tests", failures)

    for script in (WORKFORCE / "scripts").glob("*"):
        if script.is_file() and script.suffix in {".py", ".sh"}:
            require(os.access(script, os.X_OK), f"script is not executable: {script}", failures)
            require(all(ord(char) < 128 for char in script.read_text()), f"non-ASCII text in {script}", failures)
        if script.is_file() and script.suffix == ".sh":
            require(not DANGEROUS_SHELL_SNIPPET.search(script.read_text()), f"dangerous shell snippet in {script}", failures)
            require(run(["bash", "-n", str(script)]).returncode == 0, f"shell syntax check failed: {script}", failures)
    tracked_scripts = run(["git", "ls-files", ".agents/workforce/scripts"])
    require(tracked_scripts.returncode == 0, "could not list tracked workforce scripts", failures)
    for path in tracked_scripts.stdout.splitlines():
        require(Path(path).name in md_text, f"unreferenced workforce script/data file: {path}", failures)
    validate_scout_script_usage("skill-scout.sh", "usage:", failures)
    validate_scout_script_usage("agents-md-scout.sh", "usage:", failures)

    skills_ls = run(["npx", "-y", SKILLS_CLI_PACKAGE, "ls", "--json"], timeout=180)
    if skills_ls.returncode != 0:
        failures.append(f"npx skills ls failed: {skills_ls.stderr}")
    else:
        try:
            found = {entry["name"] for entry in json.loads(skills_ls.stdout)}
            missing = sorted((REQUIRED_SKILLS | REQUIRED_SUPPORT_SKILLS) - found)
            require(not missing, f"missing project skills from npx skills ls: {missing}", failures)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"could not parse npx skills ls output: {exc}")

    broad = run([str(WORKFORCE / "scripts" / "route-task.py"), "--json", EVAL_SCENARIO_REQUEST]); broad_route = json.loads(broad.stdout) if broad.returncode == 0 else {}; broad_owners = [broad_route.get("primary"), *broad_route.get("also", []), *broad_route.get("support", [])]
    require(broad_route.get("primary") == "workforce-orchestra" and {"workforce-research", "workforce-code-review", "workforce-qa-release", "workforce-eng-manager"} <= set(broad_route.get("also", [])) and set(broad_owners) == REQUIRED_SKILLS and len(broad_owners) == len(set(broad_owners)), f"broad route did not staff expected company: {broad.stdout}{broad.stderr}", failures)

    return failures
def codex_eval() -> tuple[bool, str]:
    RESULTS.mkdir(parents=True, exist_ok=True)
    output = CODEX_RESULT
    prompt = SCENARIO.read_text()
    # In this environment read-only/workspace-write sandboxing can fail before
    # Codex starts (`bwrap: loopback`); the prompt is no-edit and schema-bound.
    cmd = ["codex", "--ask-for-approval", "never", "exec", "--ephemeral", "--skip-git-repo-check", "-C", str(WORKSPACE), "-s", "danger-full-access", "--output-schema", str(SCHEMA), "-o", str(output), prompt]
    transient_details: list[str] = []
    for attempt in range(1, CODEX_EVAL_ATTEMPTS + 1):
        result = run(cmd, timeout=600)
        if result.returncode != 0:
            return False, f"codex eval failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"

        try:
            data = json.loads(output.read_text())
        except Exception as exc:  # noqa: BLE001
            return False, f"codex eval output was not valid JSON: {exc}"

        result_failures: list[str] = []
        validate_eval_result_data(data, "codex eval", result_failures)
        if result_failures:
            detail = "\n".join(result_failures)
            if attempt < CODEX_EVAL_ATTEMPTS and is_transient_codex_schema_dead_end(data):
                transient_details.append(f"attempt {attempt}: {detail}")
                continue
            if transient_details:
                detail = "\n".join([*transient_details, f"attempt {attempt}: {detail}"])
            return False, detail

        return bool(data.get("pass")), output.as_posix()

    return False, "codex eval exhausted retries"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ai", action="store_true", help="run authenticated codex exec eval")
    args = parser.parse_args()

    failures = deterministic_checks()
    if failures:
        print("DETERMINISTIC CHECKS: FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("DETERMINISTIC CHECKS: PASS")

    if args.ai:
        ok, detail = codex_eval()
        if not ok:
            print("CODEX EVAL: FAIL")
            print(detail)
            return 1
        print("CODEX EVAL: PASS")
        print(f"result: {detail}")
    else:
        print("CODEX EVAL: SKIPPED (pass --ai to run)")

    return 0
if __name__ == "__main__":
    raise SystemExit(main())
