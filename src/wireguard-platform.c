/*
 * based on WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 * RP2040 port by Marcin Kielesinski (jaszczurtd@tlen.pl)
 */

#include <Arduino.h>
#include "wireguard-platform.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "crypto.h"          // for U64TO8_BIG / U32TO8_BIG
#include <sys/time.h>        // gettimeofday()

#include "pico/rand.h"

static bool is_platform_initialized = false;

void wireguard_platform_init(void) {
  if (is_platform_initialized) return;

  is_platform_initialized = true;
}

// Key material comes from pico_rand: ring oscillator bits, the microsecond
// timer and a bus performance counter hashed into a seeded 128-bit PRNG, on
// the RP2350 also the hardware TRNG. Raw ROSC bits alone are correlated. The
// generator may be called from any core and from IRQ context; it can block
// for a few microseconds while it gathers entropy.
void wireguard_random_bytes(void *bytes, size_t size) {
    uint8_t *p = (uint8_t *)bytes;

    while (size >= 8) {
        uint64_t r = get_rand_64();
        memcpy(p, &r, 8);
        p += 8;
        size -= 8;
    }

    if (size > 0) {
        uint64_t r = get_rand_64();
        memcpy(p, &r, size);
    }
}

uint32_t wireguard_sys_now(void) {
  // we use lwIP sys_now() instead of millis() for better synchro with lwIP
  extern uint32_t sys_now(void);
  return sys_now();
}

void wireguard_tai64n_now(uint8_t *output) {
  // TAI64N for Pico W: NTP time (time()) + monotonic nano
  struct timeval tv;
  gettimeofday(&tv, NULL);
  
  uint64_t seconds = 0x400000000000000aULL + (uint64_t)tv.tv_sec;
  uint32_t nanos = (uint32_t)tv.tv_usec * 1000U;
  
  // crypto.h
  U64TO8_BIG(output + 0, seconds);
  U32TO8_BIG(output + 8, nanos);
}

bool wireguard_is_under_load(void) {
  return false;
}
