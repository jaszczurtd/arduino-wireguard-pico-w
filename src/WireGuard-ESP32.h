/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#include <Arduino.h>
#include <IPAddress.h>

class WireGuard {
private:
    bool _is_initialized = false;

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
     * - localListenPort: UDP source port to bind on the client (0 => use remotePeerPort)
     */
    bool beginAdvanced(const IPAddress& localIP,
                       const char* privateKey,
                       const char* remotePeerAddress,
                       const char* remotePeerPublicKey,
                       uint16_t remotePeerPort,
                       const IPAddress& allowedIp,
                       const IPAddress& allowedMask,
                       uint16_t localListenPort = 0);

    void end();

    bool is_initialized() const { return this->_is_initialized; }
};
