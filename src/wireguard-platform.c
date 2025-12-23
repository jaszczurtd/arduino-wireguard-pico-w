/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <Arduino.h>
#include "wireguard-platform.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "crypto.h"          // for U64TO8_BIG / U32TO8_BIG (as in your original)
#include <sys/time.h>        // gettimeofday()

// Pico SDK RNG helpers (available because Arduino-Pico is built on Pico SDK)
#include "pico/rand.h"       // get_rand_32/64
#include "lwip/sys.h"

static bool is_platform_initialized = false;

static void secure_bzero(void *p, size_t n) {
  volatile uint8_t *vp = (volatile uint8_t *)p;
  while (n--) *vp++ = 0;
}

void wireguard_platform_init() {
  if (is_platform_initialized) return;

  is_platform_initialized = true;
}

void wireguard_random_bytes(void *bytes, size_t size) {
    uint8_t *p = (uint8_t *)bytes;
    while (size) {
        uint32_t r = get_rand_32();
        size_t n = (size < sizeof(r)) ? size : sizeof(r);
        memcpy(p, &r, n);
        p += n;
        size -= n;
    }
}

uint32_t wireguard_sys_now() {
  // If you are building inside a Pico W + lwIP environment and you *really* want lwIP time,
  // you can switch this to sys_now(). In Arduino-Pico, millis() is the simplest monotonic ms tick.
  return (uint32_t)millis();
}

void wireguard_tai64n_now(uint8_t *output) {
  // TAI64N: seconds = 0x400000000000000a + UNIX seconds
  // nanos   = (microseconds * 1000)
  // Important: time must be monotonic w.r.t real world (don't go backwards), so set it via NTP and
  // ideally persist it across resets.
  struct timeval tv;
  gettimeofday(&tv, NULL);

  uint64_t seconds = 0x400000000000000aULL + (uint64_t)tv.tv_sec;
  uint32_t nanos   = (uint32_t)tv.tv_usec * 1000U;

  U64TO8_BIG(output + 0, seconds);
  U32TO8_BIG(output + 8, nanos);
}

bool wireguard_is_under_load() {
  return false;
}


