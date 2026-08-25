#!/usr/bin/env bash
# Fixture + validator for polinrider_scan.sh section 1b (config classification).
#
# Every fixture below is a REGRESSION GUARD for a specific rule. The suite used
# to print classifications with no assertions at all, so when the pad and
# longline rules were rewritten (2026-08-25) both fixtures silently stopped
# exercising the rule they were written for and the suite still "passed".
# If you change a rule in classify_config, change the fixture that pins it and
# keep an assertion on it.
set -u
FIX=/tmp/cfgtest
rm -rf "$FIX"; mkdir -p "$FIX"

# 1. INFECTED-sig: legit-looking tailwind config + whitespace pad + hard signature
{ head -c 2600 /dev/zero | tr '\0' ' '; printf 'const s="rmcej%%otb%%";\n'; } > "$FIX/tailwind.config.js"

# 2. INFECTED-marker, obfuscator.io build: the A#-####-# campaign build marker.
#    Shape of the real recovered sample (a karma.conf.js; see the internal IR record).
{ for i in $(seq 1 60); do echo "  // karma option line $i, ordinary hand-written config, padded to clear 2500B"; done
  printf 'global.i="A9-3727-2";\n'; } > "$FIX/karma.conf.js"

# 3. INFECTED-marker, older _$_ shuffle build: same marker, different spelling.
{ for i in $(seq 1 60); do echo "  module.exports.opt$i = $i; // ordinary config line, padded to clear 2500B"; done
  printf "global['!']='9-3727-2';\n"; } > "$FIX/jest.config.js"

# 4. SUSPICIOUS-pad: 250-space run anywhere in the file (rule is whole-file, 200+).
#    Was 120 spaces + tail-only; both the count and the scope changed.
{ head -c 2600 /dev/zero | tr '\0' 'x'; printf '\n'; head -c 250 /dev/zero | tr '\0' ' '; printf '\n'; } > "$FIX/postcss.config.mjs"

# 5. SUSPICIOUS-longline: >800-char unbroken NON-SPACE run on 1 of >5 lines, and
#    deliberately NO 200-space run, so the pad rule cannot mask it. This is the
#    rule the old `gsub(/ /," ")<=5` guard got backwards.
{ for i in $(seq 1 30); do echo "// vite config line $i, padded so the file clears the 2500B section-1b threshold"; done
  printf 'const a = "'; head -c 1500 /dev/zero | tr '\0' 'a'; printf '";\n'
  printf 'export default {};\n'; } > "$FIX/vite.config.ts"

# 6. THE REAL EVASION: normal multi-line config, payload appended to the end of an
#    existing line behind ~5,000 spaces of padding. This exact shape returned
#    VERDICT: CLEAN before the 2026-08-25 fixes. Must be flagged, any class.
{ for i in $(seq 1 30); do echo "  // karma config line $i"; done
  printf '};'; head -c 5000 /dev/zero | tr '\0' ' '
  head -c 1800 /dev/zero | tr '\0' 'Z'; printf '\n'; } > "$FIX/babel.config.js"

# 7. OK: large but ordinary config (many short lines) - must stay info-only.
for i in $(seq 1 80); do echo "module.exports.rule$i = { value: $i }; // padding padding padding" ; done > "$FIX/next.config.js"

OUT=$(bash "$(dirname "$0")/polinrider_scan.sh" "$FIX" 2>/dev/null)

echo "== fixture sizes =="
for f in "$FIX"/tailwind.config.js "$FIX"/karma.conf.js "$FIX"/jest.config.js \
         "$FIX"/postcss.config.mjs "$FIX"/vite.config.ts "$FIX"/babel.config.js "$FIX"/next.config.js; do
  printf '%8s bytes  %s\n' "$(wc -c < "$f" | tr -d ' ')" "$f"
done

echo
echo "== scanner section 1b output =="
echo "$OUT" | sed -n '/1b\. Oversized/,/^$/p'

PASS=1
chk() {  # chk <description> <grep -E pattern> ; fails if absent
  echo "$OUT" | grep -qE "$2" || { echo "FAIL: $1"; PASS=0; }
}
chknot() {  # fails if PRESENT
  echo "$OUT" | grep -qE "$2" && { echo "FAIL: $1"; PASS=0; }
}

chk    "hard signature not classified INFECTED"        'INFECTED CONFIG \(campaign signature present.*tailwind\.config\.js'
chk    "S1 sweep missed marker (obfuscator.io build)"  'campaign build marker \(A#-####-#\) in:.*karma\.conf\.js'
chk    "S1 sweep missed marker (_\$_ shuffle build)"    'campaign build marker \(A#-####-#\) in:.*jest\.config\.js'
chk    "1b did not classify marker as INFECTED"         'INFECTED CONFIG \(campaign build marker.*karma\.conf\.js'
chk    "1b did not classify marker as INFECTED"         'INFECTED CONFIG \(campaign build marker.*jest\.config\.js'
chk    "karma.conf.* not even scanned by 1b"           'karma\.conf\.js'
chk    "250-space run not caught by pad rule"          'whitespace padding.*postcss\.config\.mjs'
chk    "800+ char unbroken token not caught"           'injected payload shape.*vite\.config\.ts'
chk    "REAL evasion shape (pad+payload) not flagged"  '\[!\].*babel\.config\.js'
chk    "large ordinary config not info-only"           '\[i\] large config.*next\.config\.js'
chknot "large ordinary config wrongly flagged as hit"  '\[!\].*next\.config\.js'
chk    "marker must drive COMPROMISED"                 'VERDICT: COMPROMISED'

echo
echo "== verdict =="
echo "$OUT" | grep -E 'VERDICT'
echo
[ "$PASS" -eq 1 ] && echo "PASS: all 1b classification rules behave as pinned" || { echo "FAILURES above"; exit 1; }
