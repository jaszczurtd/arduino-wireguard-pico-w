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
    bool _has_kicked = false;
    uint32_t _lastKickMs = 0;

public:
    /*
     * Backward-compatible API:
     * - Allowed IPs: 0.0.0.0/0 (route everything through the tunnel)
     * Both begin() variants need the wall clock set (NTP) first: they return
     * false and log an error while time() is before 2020-01-01. Any failure
     * after that leaves the lwIP stack as it was, so begin() may be retried.
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

    /*
     * Restores the previous default netif, removes the interface and the peer,
     * stops the lwIP timer and closes the UDP socket. begin() may be called again.
     */
    void end();

    bool is_initialized() const { return this->_is_initialized; }

    /*
     * Prints the log lines that lwIP callbacks queued from IRQ context.
     * Call it from loop(); peerUp() and kickHandshake() flush the queue too.
     */
    void loop();

    /*
     * Returns true when the peer has a valid session key (i.e., handshake completed at least once).
     */
    bool peerUp(IPAddress* currentEndpointIp = nullptr, uint16_t* currentEndpointPort = nullptr) const;

    /*
     * Sends a tiny UDP probe via WG to trigger handshake (non-blocking). The first
     * call after begin() always sends; later calls within minIntervalMs return true
     * without sending. Returns false when not initialized, when probePort is 0 or
     * when the probe could not be sent.
     */
    bool kickHandshake(const IPAddress& probeIp, uint16_t probePort, uint32_t minIntervalMs = 250);
};
