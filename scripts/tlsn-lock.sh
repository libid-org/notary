#!/usr/bin/env bash
# Assert that Cargo.lock resolves every tlsnotary/tlsn crate to one commit.
# The manifest pins tlsn by tag, and a tag can move; the lock records the
# commit the tag pointed at, so this check holds the build to that commit.
#
#   tlsn-lock.sh <40-hex commit>
#
# Run from the repository root (CI's default working directory).
set -euo pipefail

expected="${1:?usage: tlsn-lock.sh <40-hex commit>}"
lock="Cargo.lock"

# tlsnotary/tlsn only: tlsn-utils and the other tlsnotary repos pin their own revs.
sources="$(grep -E '^source = "git\+https://github\.com/tlsnotary/tlsn(\.git)?[?#]' "$lock" || true)"

if [ -z "$sources" ]; then
  echo "::error::$lock has no tlsnotary/tlsn source line" >&2
  exit 1
fi

wrong="$(printf '%s\n' "$sources" | grep -v "#$expected\"\$" || true)"
if [ -n "$wrong" ]; then
  echo "::error::$lock resolves tlsn to a commit other than $expected:" >&2
  printf '%s\n' "$wrong" | sort -u >&2
  exit 1
fi

echo "$lock: $(printf '%s\n' "$sources" | wc -l | tr -d ' ') tlsn crates at $expected"
