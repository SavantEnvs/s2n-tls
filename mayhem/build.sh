#!/usr/bin/env bash
#
# mayhem/build.sh — build s2n-tls's in-tree fuzz harnesses (tests/fuzz/*.c, one binary each, plus a
# run-once *-standalone reproducer) and the unit-test subset that mayhem/test.sh runs.
# Runs inside the commit image as `mayhem` in /mayhem. Re-runnable and offline (system OpenSSL only).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
B="$SRC/build"          # `build/` is gitignored upstream and dockerignored
# Start from a clean build tree so a re-run never inherits a stale CMake cache (compiler/libcrypto probes).
rm -rf "$B"

# Unit tests that mayhem/test.sh runs (kept to a fast, assertion-heavy subset).
UNIT_TESTS="s2n_stuffer_test s2n_stuffer_hex_test s2n_stuffer_base64_test s2n_stuffer_text_test
 s2n_stuffer_network_order_test s2n_blob_test s2n_array_test s2n_map_test s2n_safety_test
 s2n_hash_test s2n_hmac_test s2n_hkdf_test s2n_certificate_parsing_test s2n_client_hello_test"

# ---- 1) project, built for the fuzzers (ASan+UBSan halting, libFuzzer coverage, DWARF 3) -------
# S2N_FUZZ_TESTING is what upstream's own S2N_FUZZ_TEST cmake mode defines.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -DS2N_FUZZ_TESTING=1"
cmake -S "$SRC" -B "$B/fuzz" -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE= \
    -DBUILD_SHARED_LIBS=OFF -DS2N_USE_CRYPTO_SHARED_LIBS=ON -DBUILD_TESTING=OFF -DS2N_INSTALL_S2NC_S2ND=OFF \
    -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS" >/dev/null
cmake --build "$B/fuzz" -j"$MAYHEM_JOBS" --target s2n

# ---- 2) testlib (shared by the harnesses), same flags -----------------------------------------
TL="$B/fuzz/testlib"
mkdir -p "$TL"
INC="-I$SRC -I$SRC/api -I$SRC/tests"
for f in "$SRC"/tests/testlib/*.c; do
    echo "$f"
done | xargs -P "$MAYHEM_JOBS" -I{} sh -c \
    '$CC '"$FUZZ_CFLAGS $INC"' -std=gnu99 -fPIC -include '"$SRC"'/utils/s2n_prelude.h -c {} -o '"$TL"'/$(basename {} .c).o'
rm -f "$TL/libtestlib.a"
ar rcs "$TL/libtestlib.a" "$TL"/*.o

# ---- 3) harnesses: fuzzer binary + standalone reproducer -------------------------------------
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"
# The harnesses open their PEMs as "../pems/..", which does not exist in Mayhem's cwd: serve them from
# the binary (fopen / X509_STORE_load_locations are wrapped at link time).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -DPEM_DIR="\"$SRC/tests/pems\"" -c "$SRC/mayhem/pem_embed.c" -o "$B/fuzz/pem_embed.o"
WRAP="-Wl,--wrap=fopen -Wl,--wrap=X509_STORE_load_locations"
LIBS="$TL/libtestlib.a $B/fuzz/lib/libs2n.a -lcrypto -lpthread -lm -ldl"

build_harness() {
    local src="$1" name
    name="$(basename "$src" .c)"
    $CC $FUZZ_CFLAGS $INC -std=gnu99 -include "$SRC/utils/s2n_prelude.h" -Wno-unknown-pragmas -Wno-unused-result \
        -c "$src" -o "$B/fuzz/$name.o"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz/$name.o" "$B/fuzz/lsan_off.o" "$B/fuzz/pem_embed.o" $WRAP $LIBS -lstdc++ \
        -o "$OUT/$name"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz/standalone_main.o" "$B/fuzz/$name.o" "$B/fuzz/lsan_off.o" "$B/fuzz/pem_embed.o" $WRAP $LIBS -lstdc++ \
        -o "$OUT/$name-standalone"
}
export -f build_harness
export B OUT INC LIBS WRAP FUZZ_CFLAGS SRC
# s2n_memory_leak_negative_test is a leak-detection canary; leak checking is off fleet-wide, so it is not built.
ls "$SRC"/tests/fuzz/*_test.c | grep -v s2n_memory_leak_negative_test \
    | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'build_harness {}'

# ---- 4) unit-test subset, normal flags (independent build; test.sh only runs it) --------------
cmake -S "$SRC" -B "$B/tests" -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER="$CC" -DBUILD_SHARED_LIBS=OFF -DS2N_USE_CRYPTO_SHARED_LIBS=ON -DBUILD_TESTING=ON \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build "$B/tests" -j"$MAYHEM_JOBS" --target $UNIT_TESTS
