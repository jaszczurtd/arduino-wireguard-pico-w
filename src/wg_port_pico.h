#pragma once

struct wireguard_handshake;
/*
 * Pico/RP2040 portability layer for the upstream WireGuard (lwIP) port.
 *
 * Notes:
 * - Keep this header C-friendly.
 * - Avoid pulling in ESP-IDF / FreeRTOS dependencies.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <Arduino.h>

#include <lwip/netif.h>
#include <lwip/ip4_addr.h>
#include <lwip/inet.h>

// ---- Logging ----
//
// On arduino-pico (no FreeRTOS) lwIP runs inside a low-priority background
// IRQ, so every WireGuard callback (receive, timer, output) executes in IRQ
// context. The logger never touches Serial from there: a line logged from an
// IRQ is formatted into a fixed-size queue, and wg_log_flush() prints the
// queue from thread context. WireGuard::loop(), peerUp() and kickHandshake()
// call wg_log_flush(). When the queue overflows, the next flush prints how
// many lines were dropped.
//
// WG_LOG_LEVEL selects the levels compiled in. Default: warnings and errors.
// Per-packet messages (send/receive) are on the verbose level.

#ifndef TAG
#define TAG "[WG] "
#endif

#define WG_LOG_LEVEL_NONE    0
#define WG_LOG_LEVEL_ERROR   1
#define WG_LOG_LEVEL_WARN    2
#define WG_LOG_LEVEL_INFO    3
#define WG_LOG_LEVEL_DEBUG   4
#define WG_LOG_LEVEL_VERBOSE 5

#ifndef WG_LOG_LEVEL
#define WG_LOG_LEVEL WG_LOG_LEVEL_WARN
#endif

// Number of lines the IRQ queue holds.
#ifndef WG_LOG_ISR_SLOTS
#define WG_LOG_ISR_SLOTS 16
#endif

// Bytes per log line, including the level prefix, newline and terminator.
#ifndef WG_LOG_LINE_MAX
#define WG_LOG_LINE_MAX 128
#endif

#ifdef __cplusplus
extern "C" {
#endif

// printf-like output without level prefix and without newline.
void dbg(const char *format, ...) __attribute__((format(printf, 1, 2)));

// One log line: "[lvl] " prefix, message, newline. Safe to call from IRQ.
void wg_logf_(char lvl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

// Prints the lines queued from IRQ context. No-op when called from an IRQ.
// Call it from one thread context only.
void wg_log_flush(void);

// True when the caller runs inside an exception or IRQ handler.
bool wg_log_in_isr(void);

#ifdef __cplusplus
} // extern "C"
#endif

// A disabled level keeps its arguments visible to the compiler (format
// checking, no unused-variable warnings) but produces no code.
#define WG_LOG_OFF_(lvl, ...) do { if (0) { wg_logf_(lvl, __VA_ARGS__); } } while (0)

#ifndef log_e
#if WG_LOG_LEVEL >= WG_LOG_LEVEL_ERROR
#define log_e(...) wg_logf_('E', __VA_ARGS__)
#else
#define log_e(...) WG_LOG_OFF_('E', __VA_ARGS__)
#endif
#endif

#ifndef log_w
#if WG_LOG_LEVEL >= WG_LOG_LEVEL_WARN
#define log_w(...) wg_logf_('W', __VA_ARGS__)
#else
#define log_w(...) WG_LOG_OFF_('W', __VA_ARGS__)
#endif
#endif

#ifndef log_i
#if WG_LOG_LEVEL >= WG_LOG_LEVEL_INFO
#define log_i(...) wg_logf_('I', __VA_ARGS__)
#else
#define log_i(...) WG_LOG_OFF_('I', __VA_ARGS__)
#endif
#endif

#ifndef log_d
#if WG_LOG_LEVEL >= WG_LOG_LEVEL_DEBUG
#define log_d(...) wg_logf_('D', __VA_ARGS__)
#else
#define log_d(...) WG_LOG_OFF_('D', __VA_ARGS__)
#endif
#endif

#ifndef log_v
#if WG_LOG_LEVEL >= WG_LOG_LEVEL_VERBOSE
#define log_v(...) wg_logf_('V', __VA_ARGS__)
#else
#define log_v(...) WG_LOG_OFF_('V', __VA_ARGS__)
#endif
#endif

#define ESP_LOGV(tag, fmt, ...) log_v("%s: " fmt, tag, ##__VA_ARGS__)


// ---- Minimal FreeRTOS compatibility (used by original code) ----
#ifndef pdMS_TO_TICKS
#define pdMS_TO_TICKS(ms) (ms)
#endif
#ifndef vTaskDelay
#define vTaskDelay(ms_ticks) delay((uint32_t)(ms_ticks))
#endif

// ---- Helpers ----
#ifndef WG_IP4_U32
#define WG_IP4_U32(ip4) (ip4_addr_get_u32((const ip4_addr_t *)(ip4)))
#endif

/*
 * ESP32 code expects tcpip_adapter_get_netif(TCPIP_ADAPTER_IF_STA) to return
 * the station netif. On Pico W (CYW43), we can expose a best-effort equivalent
 * when the CYW43 headers are available.
 */
#ifndef TCPIP_ADAPTER_IF_STA
#define TCPIP_ADAPTER_IF_STA 0
#endif

#if __has_include("pico/cyw43_arch.h")
#include "pico/cyw43_arch.h"
static inline struct netif *tcpip_adapter_get_netif(int /*ifx*/) {
    // cyw43_state.netif is the lwIP netif for STA mode.
    return &cyw43_state.netif[CYW43_ITF_STA];
}
#else
static inline struct netif *tcpip_adapter_get_netif(int /*ifx*/) {
    return NULL;
}
#endif
