#!/usr/bin/env bash
# Fixture tests for nightly_sweep.sh -- the driver, which had no suite at all
# until a review pointed out that the component deciding whether a human hears
# about a finding was the only one nobody tested.
#
# The case that matters is the one this file opens with: org_sweep.sh refusing
# to certify anything must never reach a person as a clean night. Every case
# asserts on the heartbeat as well as the exit code, because the heartbeat is
# what monitoring reads to decide the control is alive -- an exit code nobody
# is watching at 3am is not the artefact that lies.
#
# The GitHub API is stubbed on localhost rather than mocked away, so the real
# token and repository-listing paths run. The key generated here is a throwaway
# created per run and never leaves the temp directory.
#
# Run: bash test_nightly_sweep.sh

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d); trap 'cleanup' EXIT
PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

API_PID=""
cleanup() { [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null; rm -rf "$TMP"; }

# --- a throwaway App key; openssl only, no key material from anywhere else ---
openssl genrsa -out "$TMP/app.pem" 2048 >/dev/null 2>&1 \
  || { echo "openssl genrsa failed - cannot run"; exit 2; }

# --- stub GitHub API --------------------------------------------------------
# NREPOS is read at request time from a file so a single server serves every
# case with a different repository count.
echo 4 > "$TMP/nrepos"
cat > "$TMP/api.py" <<'PY'
import http.server, json, pathlib, sys, threading
STATE = pathlib.Path(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/app/installations"):
            return self._send([{"id": 1, "account": {"login": "testorg"}}])
        if self.path.startswith("/installation/repositories"):
            n = int(STATE.read_text().strip())
            page = 1
            for part in self.path.split("?")[-1].split("&"):
                if part.startswith("page="): page = int(part.split("=")[1])
            if page > 1: return self._send({"total_count": n, "repositories": []})
            return self._send({"total_count": n, "repositories": [
                {"full_name": f"testorg/r{i}", "archived": False} for i in range(1, n + 1)]})
        self.send_error(404)
    def do_POST(self):
        if "/access_tokens" in self.path:
            return self._send({"token": "stub-installation-token"})
        self.send_error(404)
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
print(srv.server_port, flush=True)
srv.serve_forever()
PY
python3 "$TMP/api.py" "$TMP/nrepos" > "$TMP/port" 2>/dev/null &
API_PID=$!
for _ in $(seq 1 50); do [ -s "$TMP/port" ] && break; sleep 0.1; done
PORT=$(cat "$TMP/port")
[ -n "$PORT" ] || { echo "stub API did not start"; exit 2; }

# --- the driver under test, beside a stub engine ----------------------------
# SWEEP is resolved as org_sweep.sh beside the driver, so the driver is copied
# out and the stub takes that name.
cp "$HERE/nightly_sweep.sh" "$TMP/nightly_sweep.sh"

# engine <<'STUB' ... STUB   writes the stub; run   executes the driver.
# Deliberately two steps: bash 3.2, which this tool still supports, mis-parses a
# heredoc nested inside $( ) when the body contains a case pattern's ")".
engine() { cat > "$TMP/org_sweep.sh"; chmod +x "$TMP/org_sweep.sh"; rm -f "$TMP/heartbeat.json"; }
run() {
  APP_ID=1 PRIVATE_KEY_PATH="$TMP/app.pem" GITHUB_API="http://127.0.0.1:$PORT" \
  HEARTBEAT_PATH="$TMP/heartbeat.json" BATCH_SIZE="${BATCH_SIZE_OVERRIDE:-2}" \
  SWEEP_ALLOWLIST="$HERE/sweep-allowlist" KNOWN_FINDINGS="$HERE/known-findings.json" \
  bash "$TMP/nightly_sweep.sh" 2>&1
}

echo "== 1. every batch aborts: the engine refused, so the night is NOT clean =="
# This is the regression. org_sweep.sh exits 2 with no RESULT lines whenever it
# declines to certify -- self-test failure, canaries missing, no rules.sh. The
# report is built by grepping RESULT lines, so zero of them used to read as
# "looked at everything, found nothing", exit 0, heartbeat written.
engine <<'STUB'
#!/usr/bin/env bash
echo "ABORT engine self-test failed - refusing to report anything as clean" >&2
exit 2
STUB
OUT=$(run); RC=$?
check "exit code" "$RC" "2"
[ -f "$TMP/heartbeat.json" ] && bad "heartbeat WRITTEN after a sweep that scanned nothing" \
                             || ok "no heartbeat written"
# Asserted on the summary, not on the notification text: with no webhook the
# notification goes out as a warning and the wording is not load-bearing. The
# summary is, and unfixed it reads "4 scanned" for a night that scanned none.
echo "$OUT" | grep -qE 'SWEEP COMPLETE.*[1-9][0-9]* scanned' \
  && bad "summary claims repositories were scanned when none were" \
  || ok "no summary claiming scanned repositories"
echo "$OUT" | grep -q 'did not run to completion' && ok "names the coverage shortfall" \
                                                  || bad "gave no reason a human can act on"

echo "== 2. one batch of several aborts: the likely case, and the worse one =="
# A token, disk or network blip on a single batch. Half the org never looked at,
# and the summary used to print the in-scope count as though it were scanned.
engine <<'STUB'
#!/usr/bin/env bash
# Succeed for r1/r2, abort for anything else.
repos=""
while [ $# -gt 0 ]; do case "$1" in --repos) repos="$2"; shift 2 ;; *) shift ;; esac; done
case "$repos" in
  *r3*|*r4*) echo "ABORT cannot create workdir" >&2; exit 2 ;;
esac
for r in $repos; do echo "RESULT $r NO_REF_HITS 0"; done
exit 0
STUB
OUT=$(run); RC=$?
check "exit code" "$RC" "2"
[ -f "$TMP/heartbeat.json" ] && bad "heartbeat written after a partial sweep" \
                             || ok "no heartbeat written on a partial sweep"
echo "$OUT" | grep -qE 'SWEEP COMPLETE.*4 scanned' && bad "claimed 4 scanned when 2 were" \
                                                   || ok "did not claim the in-scope count as scanned"

echo "== 3. a truncated batch is caught even though the engine exits 0 =="
# Not an abort: the engine returns success but reports on fewer repositories
# than it was given -- a mid-batch kill, or truncated output through the pipe.
engine <<'STUB'
#!/usr/bin/env bash
repos=""
while [ $# -gt 0 ]; do case "$1" in --repos) repos="$2"; shift 2 ;; *) shift ;; esac; done
set -- $repos
echo "RESULT $1 NO_REF_HITS 0"
exit 0
STUB
OUT=$(run); RC=$?
check "exit code" "$RC" "2"
[ -f "$TMP/heartbeat.json" ] && bad "heartbeat written after a truncated batch" \
                             || ok "no heartbeat written on a truncated batch"

echo "== 4. the happy path still passes, and reports what it reconciled =="
engine <<'STUB'
#!/usr/bin/env bash
repos=""
while [ $# -gt 0 ]; do case "$1" in --repos) repos="$2"; shift 2 ;; *) shift ;; esac; done
for r in $repos; do echo "RESULT $r NO_REF_HITS 0"; done
exit 0
STUB
OUT=$(run); RC=$?
check "exit code" "$RC" "0"
[ -f "$TMP/heartbeat.json" ] && ok "heartbeat written on a complete run" \
                             || bad "no heartbeat after a run that did reconcile"
echo "$OUT" | grep -qE 'SWEEP COMPLETE.*4 scanned' && ok "summary reports the reconciled count" \
                                                   || bad "summary lost the reconciled count"
grep -q '"scanned": *4' "$TMP/heartbeat.json" 2>/dev/null \
  && ok "heartbeat carries the reconciled count" || bad "heartbeat count is not the reconciled one"

echo "== 5. findings still reach a person =="
engine <<'STUB'
#!/usr/bin/env bash
repos=""
while [ $# -gt 0 ]; do case "$1" in --repos) repos="$2"; shift 2 ;; *) shift ;; esac; done
for r in $repos; do
  echo "===== $r ====="
  echo "!!! HARD $r refs/heads/main:evil.js"
  echo "RESULT $r INFECTED 1"
done
exit 1
STUB
OUT=$(run); RC=$?
check "exit code" "$RC" "1"
[ -f "$TMP/heartbeat.json" ] && bad "heartbeat written on a run that found malware" \
                             || ok "no success heartbeat when something was found"

echo "== 6. an oversized repository runs alone, and last =="
# The token is only needed for the clone, so a four-hour repository does not
# endanger itself - it endangers whatever clones after it on the same hour-old
# credential. Isolating it is what keeps the tail of the estate from going
# UNKNOWN every single night.
engine() { :; }   # keep the helper, but this case needs the stub to record calls
cat > "$TMP/org_sweep.sh" <<'STUB'
#!/usr/bin/env bash
repos=""
while [ $# -gt 0 ]; do case "$1" in --repos) repos="$2"; shift 2 ;; *) shift ;; esac; done
echo "BATCHCALL $repos" >> "$TMPDIR_FOR_TEST/calls"
for r in $repos; do echo "RESULT $r NO_REF_HITS 0"; done
exit 0
STUB
chmod +x "$TMP/org_sweep.sh"
rm -f "$TMP/heartbeat.json" "$TMP/calls"
OUT=$(APP_ID=1 PRIVATE_KEY_PATH="$TMP/app.pem" GITHUB_API="http://127.0.0.1:$PORT" \
  HEARTBEAT_PATH="$TMP/heartbeat.json" BATCH_SIZE=2 TMPDIR_FOR_TEST="$TMP" \
  SOLO_REPOS="testorg/r2" \
  SWEEP_ALLOWLIST="$HERE/sweep-allowlist" KNOWN_FINDINGS="$HERE/known-findings.json" \
  bash "$TMP/nightly_sweep.sh" 2>&1); RC=$?
check "exit code" "$RC" "0"
check "the oversized repo was sent alone" \
  "$(grep -c '^BATCHCALL testorg/r2$' "$TMP/calls" 2>/dev/null || true)" "1"
check "it was sent last" \
  "$(tail -1 "$TMP/calls" 2>/dev/null)" "BATCHCALL testorg/r2"
grep -q 'BATCHCALL .*r2.*r[0-9]\|BATCHCALL .*r[0-9].*r2' "$TMP/calls" 2>/dev/null \
  && bad "the oversized repo shared a batch with others" \
  || ok "no other repository shared its batch"
check "every repository still reported" \
  "$(echo "$OUT" | grep -cE 'SWEEP COMPLETE.*4 scanned')" "1"
[ -f "$TMP/heartbeat.json" ] && ok "heartbeat written with the split in place" \
                             || bad "no heartbeat after a complete split run"

echo
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
