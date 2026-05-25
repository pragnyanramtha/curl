#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  -h|--help) echo "usage: $0 <domain query>"; exit 0 ;;
esac
query="${*:-}"
if [ -z "$query" ]; then
  echo "usage: $0 <domain query>" >&2
  exit 2
fi
secret_pattern='(AKIA[0-9A-Z]{16}|gh[oprsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{35}|BEGIN [A-Z ]*PRIVATE KEY)'
if [[ "$query" =~ $secret_pattern ]]; then
  echo "refusing to send query that appears to contain a secret" >&2
  exit 2
fi

echo "AGENTS.md SCOUT QUERY: $query"
echo "NETWORK: sends the query to GitHub code search or web search. Do not include secrets, private repo names, proprietary code, or personal data."
SCOUT_TIMEOUT_SECONDS="${SCOUT_TIMEOUT_SECONDS:-45}"
MAX_SCOUT_TIMEOUT_SECONDS="${MAX_SCOUT_TIMEOUT_SECONDS:-300}"
case "$SCOUT_TIMEOUT_SECONDS" in
  ''|*[!0-9]*|0) echo "SCOUT_TIMEOUT_SECONDS must be a positive integer" >&2; exit 2 ;;
esac
[ "$SCOUT_TIMEOUT_SECONDS" -le "$MAX_SCOUT_TIMEOUT_SECONDS" ] || { echo "SCOUT_TIMEOUT_SECONDS must be <= ${MAX_SCOUT_TIMEOUT_SECONDS}" >&2; exit 2; }
echo "TIMEOUT: ${SCOUT_TIMEOUT_SECONDS}s"
echo

if command -v gh >/dev/null 2>&1; then
  echo "Trying GitHub code search through gh..."
  if results="$(timeout "$SCOUT_TIMEOUT_SECONDS" gh search code --limit 20 -- "$query filename:AGENTS.md" 2>/dev/null)"; then
    if [ -n "$results" ]; then
      printf '%s\n' "$results"
      exit 0
    fi
    echo "No AGENTS.md matches returned by gh."
  else
    echo "gh search failed or is not authenticated for code search."
  fi
  echo
fi

cat <<EOF
Use web search with these queries:
- site:github.com AGENTS.md "$query"
- site:raw.githubusercontent.com AGENTS.md "$query"
- "$query" "AGENTS.md" "skills"

Prefer repos with active maintainers, clear licensing, and instructions that match this workspace's safety rules.
EOF
