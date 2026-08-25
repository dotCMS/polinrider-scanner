#!/usr/bin/env bash
# Sweep dotCMS repos for PolinRider implant (hard IOCs + git-history check)
# Usage: bash org_sweep.sh <github-token> [workdir]
set -u
TOKEN="${1:?token required}"
WD="${2:-/tmp/org_sweep}"
AUTH="Authorization: Bearer $TOKEN"
mkdir -p "$WD"; cd "$WD"

REPOS="cloud-clientplugins dev-scripts dotcms-block-editor dotcms-php-sdk dotconnect-figma-to-uve examples internal-infrastructure new-dotcms-com new-new-devsite support support-automations"

for r in $REPOS; do
  echo "===== dotCMS/$r ====="
  rm -rf "$r"
  if ! git clone -q "https://x-access-token:${TOKEN}@github.com/dotCMS/${r}.git" "$r" 2>/dev/null; then
    echo "  CLONE FAILED (no access?)"; continue
  fi
  cd "$r"
  # HEAD working-tree hard IOCs
  hits=$(rg -l -i --hidden -g '!node_modules' -g '!.git' \
     -e 'rmcej%otb%' -e 'wuqktamceigynzbosdctpusocrjhrflovnxrt' \
     -e 'atob\(process\.env\.AUTH_API_KEY' -e 'A9-3727' -e 'helloipbot' . 2>/dev/null)
  [ -n "$hits" ] && echo "  !!! HEAD INFECTED: $hits" || echo "  HEAD clean (hard IOCs)"
  # gitignore artifact
  grep -qi 'config.bat' .gitignore 2>/dev/null && echo "  !!! config.bat in .gitignore (campaign artifact)"
  # oversized configs with padding
  while IFS= read -r f; do
    [ -s "$f" ] || continue
    tail -c 2000 "$f" | grep -qE ' {80,}' && echo "  !!! whitespace-padded config: $f ($(wc -c < "$f")B)"
  done < <(find . -maxdepth 4 -name '*.config.*' -not -path './.git/*' -not -path '*/node_modules/*' 2>/dev/null; find . -maxdepth 4 -name 'config.js' -not -path './.git/*' -not -path '*/node_modules/*' 2>/dev/null)
  # full history sweep (all branches)
  hist=$(git grep -l -i -E 'rmcej%otb%|wuqktamceigynzbosdctpusocrjhrflovnxrt|atob\(process\.env\.AUTH_API_KEY|A9-3727|helloipbot' $(git rev-list --all) 2>/dev/null | head -5)
  [ -n "$hist" ] && echo "  !!! HISTORY INFECTED:" && echo "$hist" | sed 's/^/      /' || echo "  history clean"
  headdate=$(git log -1 --format='%cI' 2>/dev/null)
  echo "  HEAD committer date: $headdate"
  cd - >/dev/null
done
