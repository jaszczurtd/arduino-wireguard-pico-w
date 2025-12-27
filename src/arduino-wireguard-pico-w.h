/*
 * Based on WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 * Arduino / Pico W port: Marcin Kielesiński
 */
#pragma once

#include <Arduino.h>
#include <IPAddress.h>

class WireGuard {
private:
    bool _is_initialized = false;
    uint32_t _lastKickMs = 0;

public:
    /*
     * Backward-compatible API:
     * - Allowed IPs: 0.0.0.0/0 (route everything through the tunnel)
     * - Listen port: remotePeerPort
     */
    bool begin(const IPAddress& localIP,
               const char* privateKey,
               const char* remotePeerAddress,
               const char* remotePeerPublicKey,
               uint16_t remotePeerPort);

    /*
     * Configurable API:
     * - allowedIp/allowedMask: what should be routed via WireGuard (e.g. 10.8.0.0/24)
     */
    bool beginAdvanced(const IPAddress& localIP,
                       const char* privateKey,
                       const char* remotePeerAddress,
                       const char* remotePeerPublicKey,
                       uint16_t remotePeerPort,
                       const IPAddress& allowedIp,
                       const IPAddress& allowedMask);

    void end();

    bool is_initialized() const { return this->_is_initialized; }

    /*
     * Returns true when the peer has a valid session key (i.e., handshake completed at least once).
     */
    bool peerUp(IPAddress* currentEndpointIp = nullptr, uint16_t* currentEndpointPort = nullptr) const;

    /*
     * Sends a tiny UDP probe via WG to trigger handshake (non-blocking). Rate-limited.
     */
    bool kickHandshake(const IPAddress& probeIp, uint16_t probePort, uint32_t minIntervalMs = 250);
};
