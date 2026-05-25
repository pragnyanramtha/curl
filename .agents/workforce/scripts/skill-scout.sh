#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  -h|--help) echo "usage: $0 <skill search query>"; exit 0 ;;
esac
query="${*:-}"
if [ -z "$query" ]; then
  echo "usage: $0 <skill search query>" >&2
  exit 2
fi
secret_pattern='(AKIA[0-9A-Z]{16}|gh[oprsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{35}|BEGIN [A-Z ]*PRIVATE KEY)'
if [[ "$query" =~ $secret_pattern ]]; then
  echo "refusing to send query that appears to contain a secret" >&2
  exit 2
fi

echo "SKILL SCOUT QUERY: $query"
echo "SKILLS CLI: ${SKILLS_CLI_PACKAGE:-skills@1.5.7}"
echo "NETWORK: sends the query to the Skills registry. Do not include secrets, private repo names, proprietary code, or personal data."
echo
SKILLS_CLI_PACKAGE="${SKILLS_CLI_PACKAGE:-skills@1.5.7}"
if [[ ! "$SKILLS_CLI_PACKAGE" =~ ^skills@[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "SKILLS_CLI_PACKAGE must match skills@<semver>" >&2; exit 2
fi
SCOUT_TIMEOUT_SECONDS="${SCOUT_TIMEOUT_SECONDS:-45}"
MAX_SCOUT_TIMEOUT_SECONDS="${MAX_SCOUT_TIMEOUT_SECONDS:-300}"
case "$SCOUT_TIMEOUT_SECONDS" in
  ''|*[!0-9]*|0) echo "SCOUT_TIMEOUT_SECONDS must be a positive integer" >&2; exit 2 ;;
esac
[ "$SCOUT_TIMEOUT_SECONDS" -le "$MAX_SCOUT_TIMEOUT_SECONDS" ] || { echo "SCOUT_TIMEOUT_SECONDS must be <= ${MAX_SCOUT_TIMEOUT_SECONDS}" >&2; exit 2; }
echo "TIMEOUT: ${SCOUT_TIMEOUT_SECONDS}s"
timeout "$SCOUT_TIMEOUT_SECONDS" npx -y "$SKILLS_CLI_PACKAGE" find "$query"
