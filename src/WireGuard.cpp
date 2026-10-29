/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "arduino-wireguard-pico-w.h"

#include <WiFi.h>
#include <lwip_wrap.h>

#include <lwip/udp.h>
#include <lwip/netif.h>
#include <lwip/ip4_addr.h>
#include <lwip/inet.h>
#include <lwip/ip_addr.h>

#include <string.h>
#include <time.h>

#include "wireguardif.h"
#include "wireguard-platform.h"
#include "wg_port_pico.h"

namespace {

// State of the single tunnel. On Arduino-Pico lwIP runs in a background IRQ,
// so everything below is touched only with the lwIP context lock held
// (LWIPMutex). The lock is recursive, so the wrapped lwIP calls may retake it.
struct netif wg_netif_instance;
struct netif *const wg_netif = &wg_netif_instance;
struct netif *previous_default_netif = nullptr;
uint8_t peer_index = WIREGUARDIF_INVALID_INDEX;
bool netif_added = false;
bool default_route_changed = false;

// The handshake carries a TAI64N timestamp and the peer rejects an initiation
// older than the last one it accepted. Arduino-Pico boots at the Unix epoch,
// so a clock before this point has not been synchronized yet.
constexpr time_t kMinimumWallClock = 1577836800; // 2020-01-01 UTC

bool resolve_ipv4(const char *host_or_ip, ip4_addr_t *out) {
    if (host_or_ip == nullptr || out == nullptr) {
        return false;
    }

    // Fast path: literal IPv4.
    if (ip4addr_aton(host_or_ip, out)) {
        return true;
    }

    // Fallback: use Arduino WiFi resolver.
    IPAddress resolved;
    // WiFi.hostByName returns 1 on success (Arduino convention).
    if (WiFi.hostByName(host_or_ip, resolved) != 1) {
        return false;
    }

    IP4_ADDR(out, resolved[0], resolved[1], resolved[2], resolved[3]);
    return true;
}

// Undoes beginAdvanced(), also after a partial start. Removing the netif
// aborts the TCP connections bound to the tunnel address and sends their RSTs
// through it, so the device is shut down last.
void teardown_locked() {
    if (default_route_changed && previous_default_netif != nullptr) {
        netif_set_default(previous_default_netif);
    }
    if (netif_added) {
        netif_remove(wg_netif);
    }
    if (peer_index != WIREGUARDIF_INVALID_INDEX) {
        (void)wireguardif_remove_peer(wg_netif, peer_index);
    }
    if (wg_netif->state != nullptr) {
        wireguardif_shutdown(wg_netif);
    }

    memset(wg_netif, 0, sizeof(*wg_netif));
    peer_index = WIREGUARDIF_INVALID_INDEX;
    netif_added = false;
    default_route_changed = false;
    previous_default_netif = nullptr;
}

// Adds the netif and the peer and starts connecting. On failure the stack is
// left as it was before the call.
bool setup_locked(const ip4_addr_t &ipaddr,
                  const ip4_addr_t &netmask,
                  const char *privateKey,
                  const char *remotePeerPublicKey,
                  const ip4_addr_t &endpoint4,
                  uint16_t remotePeerPort,
                  const IPAddress &allowedIP,
                  const IPAddress &allowedMask,
                  bool route_all) {
    // Capture the current default netif (Wi-Fi) so we can bind UDP traffic there.
    previous_default_netif = netif_default;
    if (previous_default_netif == nullptr) {
        log_e(TAG "No default netif!");
        return false;
    }
    log_d(TAG "default netif %p", (void *)previous_default_netif);

    ip4_addr_t gateway;
    IP4_ADDR(&gateway, 0, 0, 0, 0);

    wg_netif->name[0] = 'w';
    wg_netif->name[1] = 'g';

    struct wireguardif_init_data wg_init;
    memset(&wg_init, 0, sizeof(wg_init));
    wg_init.private_key = privateKey;
    wg_init.listen_port = 0;
    wg_init.bind_netif = previous_default_netif;

    // Important: netif_add expects ip4_addr_t* in this Arduino-Pico (LWIP_IPV6=0) build.
    if (netif_add(wg_netif,
                  &ipaddr,
                  &netmask,
                  &gateway,
                  &wg_init,
                  &wireguardif_init,
                  &ip_input) == nullptr) {
        log_e(TAG "netif_add() failed");
        previous_default_netif = nullptr;
        return false;
    }
    netif_added = true;

    struct wireguardif_peer peer;
    memset(&peer, 0, sizeof(peer));
    peer.public_key = remotePeerPublicKey;
    peer.preshared_key = nullptr;
    peer.allowed_ip = allowedIP;
    peer.allowed_mask = allowedMask;
    peer.endpoint_ip = endpoint4;
    peer.endport_port = remotePeerPort;

    err_t err = wireguardif_add_peer(wg_netif, &peer, &peer_index);
    if (err != ERR_OK) {
        log_e(TAG "wireguardif_add_peer() failed err=%d", (int)err);
        teardown_locked();
        return false;
    }

    netif_set_up(wg_netif);
    err = wireguardif_connect(wg_netif, peer_index);
    if (err != ERR_OK) {
        log_e(TAG "wireguardif_connect() failed err=%d", (int)err);
        teardown_locked();
        return false;
    }

    if (route_all) {
        netif_set_default(wg_netif);
        default_route_changed = true;
    }
    return true;
}

} // namespace

bool WireGuard::begin(const IPAddress &localIP,
                     const char *privateKey,
                     const char *remotePeerAddress,
                     const char *remotePeerPublicKey,
                     uint16_t remotePeerPort) {
    // Historical behavior: route everything via WireGuard.
    const IPAddress allowedIP(0, 0, 0, 0);
    const IPAddress allowedMask(0, 0, 0, 0);
    return beginAdvanced(localIP, privateKey, remotePeerAddress, remotePeerPublicKey,
                         remotePeerPort, allowedIP, allowedMask);
}

bool WireGuard::beginAdvanced(const IPAddress &localIP,
                             const char *privateKey,
                             const char *remotePeerAddress,
                             const char *remotePeerPublicKey,
                             uint16_t remotePeerPort,
                             const IPAddress &allowedIP,
                             const IPAddress &allowedMask) {
    if (_is_initialized) {
        return true;
    }
    if (privateKey == nullptr || remotePeerAddress == nullptr || remotePeerPublicKey == nullptr) {
        return false;
    }

    // The peer compares handshake timestamps, so the wall clock has to be set
    // (NTP) before the first handshake.
    const time_t now = time(nullptr);
    if (now < kMinimumWallClock) {
        log_e(TAG "wall clock not set (time()=%lu); sync NTP before begin()", (unsigned long)now);
        return false;
    }

    // Initialize platform glue (timers, RNG, etc.).
    wireguard_platform_init();

    // Resolve before taking the lwIP lock: WiFi.hostByName() waits for the DNS
    // reply, which the background IRQ cannot deliver while this core holds the lock.
    ip4_addr_t endpoint4;
    if (!resolve_ipv4(remotePeerAddress, &endpoint4)) {
        log_e(TAG "Failed to resolve endpoint '%s'", remotePeerAddress);
        return false;
    }

    // Prepare interface addresses.
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;

    IP4_ADDR(&ipaddr, localIP[0], localIP[1], localIP[2], localIP[3]);

    const bool route_all = (allowedIP == IPAddress(0, 0, 0, 0)) && (allowedMask == IPAddress(0, 0, 0, 0));
    if (route_all) {
        // /32 - only the interface address is treated as local. Default route will be switched to WG.
        IP4_ADDR(&netmask, 255, 255, 255, 255);
    } else {
        // Use the allowed IP mask as the interface netmask to get proper routing without changing default netif.
        IP4_ADDR(&netmask, allowedMask[0], allowedMask[1], allowedMask[2], allowedMask[3]);
    }

    {
        LWIPMutex lock;
        if (!setup_locked(ipaddr, netmask, privateKey, remotePeerPublicKey, endpoint4,
                          remotePeerPort, allowedIP, allowedMask, route_all)) {
            return false;
        }
    }

    _is_initialized = true;

    log_i(TAG "WireGuard initialized. local=%u.%u.%u.%u endpoint=%u.%u.%u.%u:%u allowed=%u.%u.%u.%u/%u.%u.%u.%u",
          localIP[0], localIP[1], localIP[2], localIP[3],
          ip4_addr1(&endpoint4), ip4_addr2(&endpoint4), ip4_addr3(&endpoint4), ip4_addr4(&endpoint4), (unsigned)remotePeerPort,
          allowedIP[0], allowedIP[1], allowedIP[2], allowedIP[3],
          allowedMask[0], allowedMask[1], allowedMask[2], allowedMask[3]);

    return true;
}

void WireGuard::end() {
    if (!_is_initialized) {
        return;
    }

    {
        LWIPMutex lock;
        teardown_locked();
    }

    _is_initialized = false;
    _has_kicked = false;
    _lastKickMs = 0;
    wg_log_flush();
}

void WireGuard::loop() {
    wg_log_flush();
}

bool WireGuard::peerUp(IPAddress* currentEndpointIp, uint16_t* currentEndpointPort) const {
    wg_log_flush();
    if (!_is_initialized || peer_index == WIREGUARDIF_INVALID_INDEX) return false;

    ip_addr_t ep_ip = {};
    u16_t ep_port = 0;
    err_t rc;
    {
        LWIPMutex lock;
        rc = wireguardif_peer_is_up(
            wg_netif,
            peer_index,
            (currentEndpointIp ? &ep_ip : nullptr),
            (currentEndpointPort ? &ep_port : nullptr)
        );
    }
    if (rc != ERR_OK) return false;

    if (currentEndpointIp) {
        if (IP_IS_V4(&ep_ip)) {
            const ip4_addr_t* a = ip_2_ip4(&ep_ip);
            *currentEndpointIp = IPAddress(ip4_addr1(a), ip4_addr2(a), ip4_addr3(a), ip4_addr4(a));
        } else {
            *currentEndpointIp = IPAddress(0, 0, 0, 0);
        }
    }
    if (currentEndpointPort) *currentEndpointPort = (uint16_t)ep_port;

    return true;
}

bool WireGuard::kickHandshake(const IPAddress& probeIp, uint16_t probePort, uint32_t minIntervalMs) {
    wg_log_flush();
    if (!_is_initialized || probePort == 0) return false;

    const uint32_t now = millis();
    if (_has_kicked && (uint32_t)(now - _lastKickMs) < minIntervalMs) {
        return true; // rate-limited: already kicked recently
    }

    // Non-blocking trigger: one small UDP datagram to an AllowedIPs address.
    // WiFiUDP takes the lwIP lock itself.
    WiFiUDP udp;
    const bool sent = udp.begin(0) == 1 // ephemeral local port
                   && udp.beginPacket(probeIp, probePort) == 1
                   && udp.write((uint8_t)0x00) == 1
                   && udp.endPacket() == 1;
    udp.stop();
    if (!sent) return false;

    _has_kicked = true;
    _lastKickMs = now;
    return true;
}
