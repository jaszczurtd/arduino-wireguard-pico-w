#!/usr/bin/env bash
# Builds and runs the host tests:
# - test_wireguard_helpers: the helper headers in src/ (wireguard_replay.h,
#   wireguard_pbuf.h, wireguard_allowed_ip.h, wireguard_timestamp.h) and the
#   crypto primitives (src/crypto.c, src/crypto/refc/);
# - test_wireguardif_protocol: two engines of the library (src/wireguard.c,
#   src/wireguardif.c) exchanging captured and forged datagrams.
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
# The engine includes <Arduino.h> through wg_port_pico.h; on the host it gets
# the stand-in from fakes/. Warning flags of the Arduino-Pico core at
# "warnings: all", errors on.
ENGINE_FLAGS=(-std=gnu17 -O1 -g -Wall -Wextra -Wno-type-limits -Wno-unused-parameter
              -Wno-missing-field-initializers -Werror -I"$HERE/fakes")

# lwIP itself is compiled with the test's options but without -Werror.
LWIP_UNITS=(core/pbuf core/mem core/memp core/def core/stats core/init core/inet_chksum
            core/ip core/netif core/timeouts core/udp core/ipv4/ip4 core/ipv4/ip4_addr)
for unit in "${LWIP_UNITS[@]}"; do
  gcc -std=c11 -O1 -g -Wall "${INCLUDES[@]}" -c "$LWIP_DIR/src/$unit.c" -o "$OUT/lwip_$(basename "$unit").o"
done
LWIP_HEAP_OBJS=("$OUT"/lwip_pbuf.o "$OUT"/lwip_mem.o "$OUT"/lwip_memp.o "$OUT"/lwip_def.o "$OUT"/lwip_stats.o)
LWIP_ALL_OBJS=()
for unit in "${LWIP_UNITS[@]}"; do
  LWIP_ALL_OBJS+=("$OUT/lwip_$(basename "$unit").o")
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
  "$HERE/test_wireguard_helpers.cpp" "${LWIP_HEAP_OBJS[@]}" \
  "${CRYPTO_OBJS[@]}" -o "$OUT/test_wireguard_helpers"

# The protocol test compiles wireguardif.c into itself (see the file header).
gcc "${ENGINE_FLAGS[@]}" "${INCLUDES[@]}" -c "$SRC/wireguard.c" -o "$OUT/wireguard.o"
gcc "${ENGINE_FLAGS[@]}" "${INCLUDES[@]}" -c "$HERE/test_wireguardif_protocol.c" \
  -o "$OUT/test_wireguardif_protocol.o"
gcc -o "$OUT/test_wireguardif_protocol" "$OUT/test_wireguardif_protocol.o" "$OUT/wireguard.o" \
  "${CRYPTO_OBJS[@]}" "${LWIP_ALL_OBJS[@]}"

echo "lwIP: $LWIP_DIR"
"$OUT/test_wireguard_helpers"
"$OUT/test_wireguardif_protocol"
