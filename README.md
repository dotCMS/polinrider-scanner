# polinrider-scanner

Host-side detection scanner for the DPRK "PolinRider" / Contagious Interview
supply-chain campaign (Lazarus cluster; MITRE G1052) that implanted
fetch-and-eval loaders in GitHub repos and npm packages via stolen
maintainer credentials and force-pushed, backdated commits.

## What it detects

Read-only sweep of Linux/macOS developer machines and CI runners:

- **Hard IOCs (drive the verdict):** campaign loader signatures
  (`rmcej%otb%`, scrambled-constructor string, `atob(process.env.AUTH_API_KEY`),
  `.env` files with base64 C2 values, JS disguised as fonts (`.woff`/`.woff2`
  missing magic bytes), stage-3 dropper paths (`/tmp/app`, `/tmp/.npm`
  credential staging), known-bad / suspicious persistence (LaunchAgents,
  autostart, systemd user units), VS Code auto-run tasks executing non-JS
  files with node, git hooks with malicious content
- **Heuristics (informational only):** oversized config files classified by
  content (whitespace padding, spaceless long lines, encoded blobs,
  string-shuffle arrays), loader-family patterns (campaign markers, RPC
  hostnames) scoped to project source trees

## Usage

```bash
bash polinrider_scan.sh [target_dir] | tee scan_$(hostname)_$(date +%F).log
```

- `target_dir` (optional): directory to scan (repo/project tree); defaults to `$PWD`
- Auto-uses `rg` (ripgrep) if on PATH; falls back to grep
- Sections 1/1b/1c/4 (signatures, configs, fonts, tasks/hooks) scan `target_dir`;
  sections 2/3/5 (droppers, persistence, credential stores) are always host-wide
- Exit codes: `0` = CLEAN (host-side), `2` = SUSPECT, `1` = COMPROMISED
- Final line `VERDICT: <value>` is grep-friendly for fleet automation

Caveat: a CLEAN result cannot prove the implant never ran — DNS caches are
short-lived and the campaign rotates C2. Correlate with proxy/DNS/firewall
logs for the campaign's Vercel staging and public blockchain-RPC egress.

## Tests

Fixture-based test suites validate each detection (and caught three real
bugs during development):

```bash
bash test_rg_detection.sh
bash test_config_classification.sh
bash test_reinfection_vectors.sh
```

## Contents

- `polinrider_scan.sh` — the scanner (pure-ASCII bash, macOS bash-3.2 compatible)
- `test_*.sh` — fixture test suites
- `incident-report-polinrider.md` — example incident report from the
  the affected organization compromise (references below)
- `HANDOFF.md` — IR session handoff notes (scanner history, FP triage log)

## References

- OpenSourceMalware: Neutralinojs/PolinRider research
  (https://opensourcemalware.com/blog/neutralinojs-compromised-in-dprk-attack)
- Socket: PolinRider supply-chain campaign
  (https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands)
- MITRE ATT&CK: S1245 (InvisibleFerret), G1052 (Contagious Interview)

## License

Copyright (C) 2026 dotCMS LLC

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE) for the full text.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

GPLv3 is the license dotCMS core itself carried before it moved to the Business
Source License. It is deliberate here: anyone — individual, company or vendor —
may run this scanner, for any purpose including commercial use, at no cost. What
copyleft prevents is enclosure: if you distribute a modified version, those
modifications ship under GPLv3 with source, so improvements to the detection
rules come back to everyone relying on them.

Contributions are welcome and are accepted under the same license.

All third-party components incorporated into this repository remain under the
original license provided by the owner of the applicable component.
