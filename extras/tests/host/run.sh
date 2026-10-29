#!/usr/bin/env bash
# Builds and runs the host tests of the helper headers in src/
# (wireguard_replay.h, wireguard_pbuf.h, wireguard_allowed_ip.h) and of the
# crypto primitives (src/crypto.c, src/crypto/refc/).
# Needs gcc/g++ and the lwIP sources. LWIP_DIR defaults to the lwIP bundled
# with the newest installed Arduino-Pico core; BUILD_DIR defaults to
# extras/tests/host/.build.
set -eu
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SRC="$HERE/../../../src"

if [ -z "${LWIP_DIR:-}" ]; then
  LWIP_DIR="$(ls -d "$HOME"/.arduino15/packages/rp2040/hardware/rp2040/*/pico-sdk/lib/lwip 2>/dev/null | sort -V | tail -1 || true)"
fi
if [ -z "$LWIP_DIR" ] || [ ! -f "$LWIP_DIR/src/core/pbuf.c" ]; then
  echo "lwIP sources not found; set LWIP_DIR to a checkout that has src/core/pbuf.c" >&2
  exit 2
fi

OUT="${BUILD_DIR:-$HERE/.build}"
mkdir -p "$OUT"
INCLUDES=(-I"$HERE" -I"$SRC" -I"$LWIP_DIR/src/include")

# lwIP itself is compiled with the test's options but without -Werror.
for unit in pbuf mem memp def stats; do
  gcc -std=c11 -O1 -g -Wall "${INCLUDES[@]}" -c "$LWIP_DIR/src/core/$unit.c" -o "$OUT/$unit.o"
done

# The library's crypto, as shipped, with the library warning flags.
CRYPTO=(crypto.c crypto/refc/blake2s.c crypto/refc/chacha20.c crypto/refc/chacha20poly1305.c
        crypto/refc/poly1305-donna.c crypto/refc/x25519.c)
CRYPTO_OBJS=()
for unit in "${CRYPTO[@]}"; do
  obj="$OUT/$(basename "$unit" .c).o"
  gcc -std=c11 -O1 -g -Wall -Wextra -Werror "${INCLUDES[@]}" -c "$SRC/$unit" -o "$obj"
  CRYPTO_OBJS+=("$obj")
done

g++ -std=c++17 -O1 -g -Wall -Wextra -Werror "${INCLUDES[@]}" \
  "$HERE/test_wireguard_helpers.cpp" "$OUT"/pbuf.o "$OUT"/mem.o "$OUT"/memp.o "$OUT"/def.o "$OUT"/stats.o \
  "${CRYPTO_OBJS[@]}" -o "$OUT/test_wireguard_helpers"

echo "lwIP: $LWIP_DIR"
"$OUT/test_wireguard_helpers"
