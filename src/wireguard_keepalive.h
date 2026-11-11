/*
 * Persistent keepalive of the peer. WireGuard sends nothing on an idle
 * session, so a NAT mapping in front of the device expires and the server
 * cannot reach it until the device sends again. A persistent keepalive sends
 * an empty, authenticated packet after this many seconds without traffic and
 * keeps the session alive and renewed on its own. 25 s is the interval the
 * WireGuard documentation recommends for peers behind NAT, 0 disables it.
 */
#ifndef WIREGUARD_KEEPALIVE_H
#define WIREGUARD_KEEPALIVE_H

#include <stdbool.h>
#include <stdint.h>

#define WIREGUARD_KEEPALIVE_DEFAULT_SECONDS 25u
// Reject-After-Time of the protocol: a session expires after 180 s without
// traffic, so a longer interval cannot keep one alive.
#define WIREGUARD_KEEPALIVE_MAX_SECONDS 180u

// 0 (disabled) up to WIREGUARD_KEEPALIVE_MAX_SECONDS.
static inline bool wireguard_keepalive_seconds_valid(uint16_t seconds) {
  return seconds <= WIREGUARD_KEEPALIVE_MAX_SECONDS;
}

#endif
