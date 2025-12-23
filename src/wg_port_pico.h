#pragma once

struct wireguard_handshake;
/*
 * Pico/RP2040 portability layer for the upstream WireGuard (lwIP) port.
 *
 * Notes:
 * - Keep this header C-friendly.
 * - Avoid pulling in ESP-IDF / FreeRTOS dependencies.
 */

#include <stdio.h>
#include <stdarg.h>

#include <Arduino.h>

#include <lwip/netif.h>
#include <lwip/ip4_addr.h>
#include <lwip/inet.h>

// ---- Logging (ESP-IDF style -> printf) ----
#ifndef TAG
#define TAG "[WG] "
#endif

static inline void wg_logf_(const char *lvl, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[%s] ", lvl);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

#ifndef log_v
#define log_v(...) wg_logf_("V", __VA_ARGS__)
#endif
#ifndef log_d
#define log_d(...) wg_logf_("D", __VA_ARGS__)
#endif
#ifndef log_i
#define log_i(...) wg_logf_("I", __VA_ARGS__)
#endif
#define ESP_LOGV(tag, fmt, ...) wg_logf_("V", "%s" fmt, tag, ##__VA_ARGS__)
#ifndef log_w
#define log_w(...) wg_logf_("W", __VA_ARGS__)
#endif
#ifndef log_e
#define log_e(...) wg_logf_("E", __VA_ARGS__)
#endif

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
