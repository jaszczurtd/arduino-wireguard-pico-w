/*
 * Greatest handshake timestamp a new peer starts with. Handshake initiations
 * carry a TAI64N timestamp that has to grow (WireGuard whitepaper, 5.1), and
 * a peer added with an all-zero value accepts one replayed old initiation of
 * the server. The client therefore starts the peer from the synchronized
 * clock minus a tolerance for the clock difference to the server, or from
 * the greatest timestamp the engine accepted in the previous session with
 * the same server key, whichever is greater. Rejecting a server initiation
 * does not stop the tunnel, because the client initiates its own handshakes.
 */
#ifndef WIREGUARD_TIMESTAMP_H
#define WIREGUARD_TIMESTAMP_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WIREGUARD_TIMESTAMP_BYTES 12u
#define WIREGUARD_TIMESTAMP_SECONDS_BYTES 8u
#define WIREGUARD_TIMESTAMP_CLOCK_TOLERANCE_SECONDS 120u
// Base64 text of a 32-byte public key and its terminator.
#define WIREGUARD_TIMESTAMP_KEY_TEXT_CAPACITY (4u * ((32u + 2u) / 3u) + 1u)

// The greatest timestamp accepted from one server key, kept across sessions.
// An empty key means nothing is kept.
typedef struct {
  char peer_key[WIREGUARD_TIMESTAMP_KEY_TEXT_CAPACITY];
  uint8_t timestamp[WIREGUARD_TIMESTAMP_BYTES];
} wireguard_timestamp_keeper_t;

// Copies a server key that fits the buffer; anything longer is not a valid
// key and leaves the buffer empty.
static inline void
wireguard_timestamp_copy_key(char destination[WIREGUARD_TIMESTAMP_KEY_TEXT_CAPACITY],
                             const char *key) {
  destination[0] = '\0';
  if ((key != NULL) &&
      (memchr(key, '\0', WIREGUARD_TIMESTAMP_KEY_TEXT_CAPACITY) != NULL)) {
    memcpy(destination, key, strlen(key) + 1u);
  }
}

// The greatest timestamp for a new peer of 'peer_key': 'now' minus the
// tolerance with the nanoseconds cleared (all zero when 'now' is not past the
// tolerance), or the kept value of the same key when that is greater.
static inline void
wireguard_timestamp_seed(const wireguard_timestamp_keeper_t *kept,
                         const uint8_t now[WIREGUARD_TIMESTAMP_BYTES],
                         const char *peer_key,
                         uint8_t out[WIREGUARD_TIMESTAMP_BYTES]) {
  uint64_t seconds = 0u;
  size_t index;

  for (index = 0u; index < WIREGUARD_TIMESTAMP_SECONDS_BYTES; ++index) {
    seconds = (seconds << 8u) | now[index];
  }
  memset(out, 0, WIREGUARD_TIMESTAMP_BYTES);
  if (seconds > WIREGUARD_TIMESTAMP_CLOCK_TOLERANCE_SECONDS) {
    seconds -= WIREGUARD_TIMESTAMP_CLOCK_TOLERANCE_SECONDS;
    for (index = WIREGUARD_TIMESTAMP_SECONDS_BYTES; index > 0u; --index) {
      out[index - 1u] = (uint8_t)(seconds & 0xFFu);
      seconds >>= 8u;
    }
  }
  if ((kept != NULL) && (peer_key != NULL) && (kept->peer_key[0] != '\0') &&
      (strcmp(kept->peer_key, peer_key) == 0) &&
      (memcmp(kept->timestamp, out, WIREGUARD_TIMESTAMP_BYTES) > 0)) {
    memcpy(out, kept->timestamp, WIREGUARD_TIMESTAMP_BYTES);
  }
}

// Keeps the greatest timestamp the engine reported for 'peer_key' when the
// session ends. An empty key keeps nothing.
static inline void
wireguard_timestamp_keep(wireguard_timestamp_keeper_t *kept,
                         const char *peer_key,
                         const uint8_t greatest[WIREGUARD_TIMESTAMP_BYTES]) {
  if ((kept == NULL) || (peer_key == NULL) || (peer_key[0] == '\0')) {
    return;
  }
  wireguard_timestamp_copy_key(kept->peer_key, peer_key);
  memcpy(kept->timestamp, greatest, WIREGUARD_TIMESTAMP_BYTES);
}

#endif
