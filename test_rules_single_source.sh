#!/usr/bin/env bash
# Guards the one property that makes rules.sh worth having: that it is the ONLY
# place a detection rule is written down.
#
# The rules used to live in polinrider_scan.sh and org_sweep.sh separately. They
# drifted -- the sweep matched the campaign tag as the literal 'A9-3727' long
# after the scanner had generalised it, leaving the sweep blind to the wave-1
# variant on every run it ever performed. Nobody noticed, because a rule that
# has drifted still reports CLEAN.
#
# Run: bash test_rules_single_source.sh

set -uo pipefail
cd "$(dirname "$0")"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); }

echo "== rules.sh loads and yields both sets =="
# shellcheck source=rules.sh
. ./rules.sh
[ -n "${POLINRIDER_RULES_VERSION:-}" ] && ok "version is set ($POLINRIDER_RULES_VERSION)" || bad "no version"
for ctx in repo host; do
  n=$(polinrider_sigs_for "$ctx" | grep -c .)
  [ "$n" -gt 0 ] && ok "$ctx set is non-empty ($n signatures)" || bad "$ctx set is empty"
done
polinrider_sigs_for bogus >/dev/null 2>&1 && bad "an unknown context was accepted" || ok "unknown context is rejected"

echo "== the two shared indicators are in BOTH sets =="
for sig in 'rmcej%otb%' 'wuqktamceigynzbosdctpusocrjhrflovnxrt'; do
  in_repo=$(polinrider_sigs_for repo | grep -cxF "$sig")
  in_host=$(polinrider_sigs_for host | grep -cxF "$sig")
  [ "$in_repo" = 1 ] && [ "$in_host" = 1 ] && ok "$sig in both" || bad "$sig missing from one set"
done

echo "== the deliberate split is preserved =="
# Repo scans need the bare key: it is the only thing that sees a .env carrier.
polinrider_sigs_for repo | grep -qxF 'AUTH_API_KEY' \
  && ok "repo set has the bare AUTH_API_KEY" || bad "repo set lost the bare AUTH_API_KEY"
# Host scans must NOT: the bare key collides with docs and tool caches, and
# HANDOFF item 8a pins that. This assertion is the pin.
polinrider_sigs_for host | grep -qxF 'AUTH_API_KEY' \
  && bad "host set gained the bare AUTH_API_KEY (known FP class)" || ok "host set still uses the narrow form"
polinrider_sigs_for host | grep -qxF 'atob(process.env.AUTH_API_KEY' \
  && ok "host set has the exact-usage form" || bad "host set lost the exact-usage form"
# The bare tag belongs to repo scans; on a host it appears in Claude transcripts.
polinrider_sigs_for repo | grep -qxF '9-3727-2' \
  && ok "repo set has the bare campaign tag" || bad "repo set lost the bare campaign tag"

echo "== no script defines a rule of its own =="
# Any signature literal appearing outside rules.sh, other than in a comment or
# in a self-test canary, is a second source of truth waiting to drift.
for f in polinrider_scan.sh org_sweep.sh; do
  hits=$(grep -n "rmcej%otb%\|wuqktamceigynzbosdctpusocrjhrflovnxrt\|atob(process\.env\.AUTH_API_KEY\|774f4632" "$f" \
         | grep -v '^[0-9]*: *#' || true)
  [ -z "$hits" ] && ok "$f defines no signature inline" || { bad "$f defines signatures inline:"; echo "$hits" | sed 's/^/        /'; }
  # Sourced indirectly via RULES_FILE, so check both halves: that the path is
  # built from rules.sh, and that it is actually sourced.
  if grep -q 'RULES_FILE=.*rules\.sh' "$f" && grep -qF '. "$RULES_FILE"' "$f"; then
    ok "$f sources rules.sh"
  else
    bad "$f does not source rules.sh"
  fi
  grep -qF 'exit 2' "$f" && ok "$f aborts if rules.sh is missing" || bad "$f would run without rules.sh"
done

echo "== the marker still matches every known build, including a rotated one =="
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
for build in "global['!']='9-3727-2';" 'global.i="A9-3727-2";' 'global.i="A9-3727-3";' 'global.i="A9-3727-9";'; do
  printf '%s\n' "$build" > "$t/c"
  grep -qE "$POLINRIDER_BUILD_MARKER" "$t/c" && ok "marker matches ${build:0:24}..." || bad "marker MISSED $build"
done
printf 'global.info = "hello";\n' > "$t/c"
grep -qE "$POLINRIDER_BUILD_MARKER" "$t/c" && bad "marker matched a negative canary" || ok "marker rejects a negative canary"

echo
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
