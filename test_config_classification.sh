#!/usr/bin/env bash
# Test fixture + validator for polinrider_scan.sh section 1b (config classification)
set -u
FIX=/tmp/cfgtest
rm -rf "$FIX"; mkdir -p "$FIX"

# 1. INFECTED: legit-looking tailwind config + trailing whitespace pad + signature
{ head -c 2600 /dev/zero | tr '\0' ' '; printf 'const s="rmcej%%otb%%";\n'; } > "$FIX/tailwind.config.js"

# 2. SUSPICIOUS-pad: big config, long space run at end, no signature
{ head -c 2600 /dev/zero | tr '\0' 'x'; printf '\n'; head -c 120 /dev/zero | tr '\0' ' '; printf '\n'; } > "$FIX/postcss.config.mjs"

# 3. SUSPICIOUS-longline: >2500B total with a >800-char single line, no signature
{ printf '// vite config\nconst a = "'; head -c 2600 /dev/zero | tr '\0' 'a'; printf '";\nexport default {};\n'; } > "$FIX/vite.config.ts"

# 4. OK: large but normal config (many short lines)
for i in $(seq 1 80); do echo "module.exports.rule$i = { value: $i }; // padding padding padding" ; done > "$FIX/next.config.js"

echo "== expected classification =="
for f in "$FIX"/tailwind.config.js "$FIX"/postcss.config.mjs "$FIX"/vite.config.ts "$FIX"/next.config.js; do
  wc -c < "$f" | tr -d ' ' | xargs -I{} echo "{} bytes  $f"
done

echo
echo "== scanner section 1b output =="
cd "$FIX" && bash /workspace/polinrider_scan.sh 2>/dev/null | sed -n '/1b\. Oversized/,/^$/p'

echo "== verdict =="
cd "$FIX" && bash /workspace/polinrider_scan.sh 2>/dev/null | grep -E 'VERDICT'
