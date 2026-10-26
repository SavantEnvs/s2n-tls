#!/usr/bin/env bash
#
# mayhem/test.sh — RUN s2n-tls's own unit tests (a subset built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Each s2n unit test prints "PASSED <n> tests" on success, where <n> is the number of assertions it
# executed. Assert the exact known count: a neutered binary prints nothing, a broken library
# fails an assertion (exit 1) or changes the count.
BIN="$SRC/build/tests/bin"
cd "$SRC/tests/unit"

# <test>:<expected assertion count>
EXPECTED="s2n_stuffer_test:1139
s2n_stuffer_hex_test:265094
s2n_stuffer_base64_test:4355
s2n_stuffer_text_test:124
s2n_stuffer_network_order_test:589972
s2n_blob_test:49
s2n_array_test:1887
s2n_map_test:65664
s2n_safety_test:66589
s2n_hash_test:460
s2n_hmac_test:464
s2n_hkdf_test:172
s2n_certificate_parsing_test:166
s2n_client_hello_test:979"

passed=0 ; failed=0
for entry in $EXPECTED; do
  t="${entry%%:*}" ; want="${entry##*:}"
  if [ ! -x "$BIN/$t" ]; then echo "MISSING test binary $BIN/$t (mayhem/build.sh should have built it)" >&2; failed=$((failed+1)); continue; fi
  out="$("$BIN/$t" 2>&1)" ; rc=$?
  got="$(printf '%s\n' "$out" | sed -n 's/.*PASSED *\([0-9][0-9]*\) tests.*/\1/p' | tail -1)"
  if [ "$rc" -eq 0 ] && [ "$got" = "$want" ]; then
    echo "ok   $t ($got assertions)"; passed=$((passed+1))
  else
    echo "FAIL $t: exit=$rc passed-count='${got}' expected=$want" >&2; printf '%s\n' "$out" | tail -5 >&2; failed=$((failed+1))
  fi
done

# Harness init: these fuzz harnesses load PEMs in their init (or per input). Run each once from a
# directory with no ../pems — as Mayhem does — and require that init succeeds and a seed runs clean.
for h in s2n_client_key_recv_fuzz_test s2n_cert_req_recv_test s2n_tls13_cert_req_recv_test \
         s2n_tls13_cert_verify_recv_test s2n_certificate_extensions_parse_test \
         s2n_client_cert_recv_test s2n_server_cert_recv_test; do
  seed="$(ls "$SRC/mayhem/$h/testsuite"/* 2>/dev/null | head -1)"
  if [ -z "$seed" ] || [ ! -x "/mayhem/$h-standalone" ]; then echo "FAIL $h: missing seed or standalone binary" >&2; failed=$((failed+1)); continue; fi
  wd="$(mktemp -d)"
  out="$(cd "$wd" && "/mayhem/$h-standalone" "$seed" 2>&1)" ; rc=$?
  rm -rf "$wd"
  if [ "$rc" -eq 0 ] && ! printf '%s\n' "$out" | grep -q "did not return S2N_SUCCESS"; then
    echo "ok   $h (init + seed from a cwd without ../pems)"; passed=$((passed+1))
  else
    echo "FAIL $h: exit=$rc" >&2; printf '%s\n' "$out" | tail -5 >&2; failed=$((failed+1))
  fi
done

emit_ctrf "s2n-unit" "$passed" "$failed" 0
