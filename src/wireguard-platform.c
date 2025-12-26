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

#include "hardware/regs/rosc.h"
#include "hardware/regs/addressmap.h"

static bool is_platform_initialized = false;

static void secure_bzero(void *p, size_t n) {
  volatile uint8_t *vp = (volatile uint8_t *)p;
  while (n--) *vp++ = 0;
}

void wireguard_platform_init() {
  if (is_platform_initialized) return;

  is_platform_initialized = true;
}

// Hardware RNG for Pico - Ring Oscillator
static uint32_t get_hardware_random() {
    uint32_t random = 0;
    volatile uint32_t *rnd_reg = (uint32_t *)(ROSC_BASE + ROSC_RANDOMBIT_OFFSET);
    
    for (int i = 0; i < 32; i++) {
        random <<= 1;
        random |= (*rnd_reg) & 1;
    }
    
    return random;
}

void wireguard_random_bytes(void *bytes, size_t size) {
    uint8_t *p = (uint8_t *)bytes;
    uint32_t r;
    
    while (size >= 4) {
        r = get_hardware_random();
        memcpy(p, &r, 4);
        p += 4;
        size -= 4;
    }
    
    if (size > 0) {
        r = get_hardware_random();
        memcpy(p, &r, size);
    }
}

uint32_t wireguard_sys_now() {
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

bool wireguard_is_under_load() {
  return false;
}
