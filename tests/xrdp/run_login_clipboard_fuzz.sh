#!/bin/bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
build=${XRDP_BUILD_DIR:?Set XRDP_BUILD_DIR to a configured legacy build with make completed}
output=${XRDP_FUZZ_DIR:-/tmp/xrdp-login-clipboard-fuzz}
clang=${CLANG:-clang}
mkdir -p "$output/corpus"
"$clang" -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined \
  -I"$build" -I"$repo/common" -I"$repo/xrdp" -I"$repo/libxrdp" \
  -Wl,--wrap=OPENSSL_cleanse "$repo/tests/xrdp/fuzz_login_clipboard.c" \
  -L"$build/common/.libs" -Wl,-rpath,"$build/common/.libs" \
  -lcommon -lssl -lcrypto -o "$output/fuzz_login_clipboard"
"$output/fuzz_login_clipboard" -seed=816862 -max_len=16384 -timeout=5 \
  -rss_limit_mb=512 -max_total_time="${XRDP_FUZZ_SECONDS:-60}" \
  "$output/corpus" "$@"
