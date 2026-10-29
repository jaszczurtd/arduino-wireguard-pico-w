# WireGuard-Raspberry Pi Pico W / RP2040 (2350) (port of Wireguard-ESP32)

This library is a **port** of the original **WireGuard-ESP32** project to **Raspberry Pi Pico(2) W (RP2040/2350 + CYW43)** using the **Arduino-Pico (Earle Philhower) core** and **lwIP**.

The goal of the port is to keep the original API as intact as possible, while replacing ESP-IDF / ESP32-specific dependencies with a small Pico W compatibility layer.

## Credits

- Original project / API: the WireGuard-ESP32 library and its upstream dependencies (see `LICENSE`).
- Pico(2) W / RP2040 / 2350 port: **Marcin Kielesiński** (this repository).

## What changed in this port (high level)

The original library targets ESP32 and depends on ESP-IDF pieces. For Pico W (Arduino-Pico + lwIP) this port replaces or adapts the following:

- **ESP logging** (`ESP_LOGx`) replaced with a small `Serial` logger that is safe to call from lwIP callbacks (see [Logging](#logging)).
- **`tcpip_adapter_*`** (ESP-IDF networking glue) replaced with a Pico/lwIP shim.
- **Netif lookup** simplified: on Pico W the STA interface maps to **lwIP's default netif** (`netif_default`).
- **Platform glue** moved into `src/wg_port_pico.h` and `src/wireguard-platform.c`.
- **Build fixes** for ARM GCC (RP2040 toolchain), including a warning fix in `x25519.c` (treat `a24` as an 8-limb field element to avoid false-positive overread warnings).
- **Data path**: encapsulated UDP leaves explicitly through the Wi-Fi interface (so full-tunnel routing cannot loop back into the tunnel), received chained `pbuf`s are coalesced before parsing, the anti-replay window is an RFC 6479 style ring of 8192 counters that accepts counter zero once, and received inner packets are checked against AllowedIPs by their source address.

## Requirements

- Raspberry Pi Pico(2) W (RP2040 / 2350)
- Arduino IDE / Arduino CLI
- Arduino-Pico core (Earle Philhower)
- WiFi enabled (CYW43)
- IPv4 networking (WireGuard endpoint by IPv4 literal or hostname is supported)
- Wall clock synchronized (NTP) before `begin()`; the handshake carries a timestamp

## Usage (example)

```cpp
#include <WiFi.h>
#include <time.h>
#include "arduino-wireguard-pico-w.h"

WireGuard wg;

static const char* WIFI_SSID = "your-ssid";
static const char* WIFI_PASS = "your-pass";

// WireGuard keys (base64 strings, like in wg-quick)
static const char* WG_PRIVATE_KEY = "YOUR_PRIVATE_KEY_BASE64";
static const char* WG_SERVER_PUBLIC_KEY = "SERVER_PUBLIC_KEY_BASE64";

// Example configuration:
// - local tunnel address: 10.8.0.50
// - endpoint: 203.0.113.10:10000 (an IPv4 literal or a host name)
// - allowed IPs: 10.8.0.0/24, so only the VPN range goes through the tunnel.
//   0.0.0.0/0 here (or begin() instead of beginAdvanced()) makes a full
//   tunnel: the interface becomes the default route and every later
//   connection, DNS included, goes through WireGuard.
static const IPAddress WG_LOCAL_IP(10, 8, 0, 50);
static const char* WG_ENDPOINT = "203.0.113.10";
static const uint16_t  WG_ENDPOINT_PORT = 10000;

static const IPAddress WG_ALLOWED_IP(10, 8, 0, 0);
static const IPAddress WG_ALLOWED_MASK(255, 255, 255, 0);

// A host inside the allowed range; the UDP probe only triggers the handshake.
static const IPAddress WG_PEER_IP(10, 8, 0, 1);

bool time_synchro(const char *tz, char *dest, int dest_size) {
  if(tz != NULL) {
    setenv("TZ", tz, 1);
    tzset();
  }

  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  const time_t MIN_VALID_EPOCH = 1672531200; // 2023-01-01 00:00:00 UTC
  time_t now = 0;

  for (int i = 0; i < 30; i++) {   // 30 * 500ms = 15s
    now = time(nullptr);
    if (now >= MIN_VALID_EPOCH) break;
    delay(500);
  }

  if (now < MIN_VALID_EPOCH) {
    return false;
  } else {
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    strftime(dest, dest_size, "%Y-%m-%d %H:%M:%S", &tm_now);
  }  
  return true;
}

void setup() {
  Serial.begin(115200);

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(250);
  }

  //local time synchro
  char buftime[32];
  if(time_synchro("CET-1CEST,M3.5.0/2,M10.5.0/3", buftime, sizeof(buftime))) {
    Serial.printf("time: %s\n", buftime);    
  } else {
    Serial.printf("NTP sync failed. check WiFi/DNS/UDP 123.\n");
  }

  // beginAdvanced(...) with a range narrower than 0.0.0.0/0 = split tunnel:
  // only WG_ALLOWED_IP/WG_ALLOWED_MASK goes through WireGuard.
  if (!wg.beginAdvanced(
        WG_LOCAL_IP,
        WG_PRIVATE_KEY,
        WG_ENDPOINT,
        WG_SERVER_PUBLIC_KEY,
        WG_ENDPOINT_PORT,
        WG_ALLOWED_IP,
        WG_ALLOWED_MASK
      )) {
    Serial.println("WireGuard initialization failed.");
    while (true) {
      delay(1000);
    }
  }

  // The handshake starts with the first packet sent into the tunnel; see loop().
}

void loop() {
  wg.loop();  // prints the log lines queued by lwIP callbacks (IRQ context)

  if (!wg.peerUp()) {
    // No session key yet: send a tiny UDP probe to start the handshake
    // (rate limited, 9 = discard port, no service needed on the peer).
    wg.kickHandshake(WG_PEER_IP, 9);
    delay(100);
    return;
  }

  // Your application code here: WiFiClient/WiFiUDP to 10.8.0.0/24 goes
  // through the tunnel, everything else leaves through WiFi as before.
  delay(100);
}
```

## API summary

- `begin(localIP, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort)`
  - Backward-compatible mode.
  - Uses full-tunnel routing (`AllowedIPs = 0.0.0.0/0`): the WireGuard interface
    becomes lwIP's default route, so every connection opened afterwards, DNS
    included, goes through the tunnel. Resolve names and sync NTP before `begin()`.

- `beginAdvanced(localIP, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort, allowedIp, allowedMask)`
  - Split-tunnel mode.
  - Routes only `allowedIp/allowedMask` through WireGuard.

- Both `begin()` variants return `false` and log an error while the wall clock
  is before 2020-01-01 (NTP not done yet). Any later failure, for example an
  invalid peer key, leaves the lwIP stack as it was, so `begin()` can be retried.

- `end()`
  - Restores the previous default netif, removes the interface and the peer,
    stops the lwIP timer and closes the UDP socket. `begin()` may be called again.

- `is_initialized()`
  - Returns whether WireGuard interface setup has completed.

- `loop()`
  - Prints the log lines that lwIP callbacks queued from IRQ context.
  - Call it from your `loop()`; `peerUp()` and `kickHandshake()` flush the queue too.

- `peerUp(...)`
  - Returns `true` when a valid session key exists.

- `kickHandshake(probeIp, probePort, minIntervalMs)`
  - Sends a tiny UDP probe to trigger handshake in a non-blocking way.
  - The first call after `begin()` always sends; later calls within
    `minIntervalMs` return `true` without sending. Returns `false` when
    `probePort` is 0 or the probe could not be sent.

## Logging

On Arduino-Pico the lwIP callbacks (receive, timers, output) run inside a
background IRQ, so the library never writes to `Serial` from them. A line logged
from IRQ context goes to a small queue; `WireGuard::loop()`, `peerUp()` and
`kickHandshake()` print the queue from your sketch. When the queue overflows,
the next flush prints how many lines were dropped.

`WG_LOG_LEVEL` selects the levels compiled in (build flag, for example
`-DWG_LOG_LEVEL=5` in `build.extra_flags`):

| Value | Level | Content |
|---|---|---|
| 0 | none | |
| 1 | error | failures |
| 2 | warn (default) | failures and suspicious packets |
| 3 | info | handshakes, interface start |
| 4 | debug | initialization details |
| 5 | verbose | every sent and received packet |

Queue size: `WG_LOG_ISR_SLOTS` (default 16 lines). Line length including the
level prefix: `WG_LOG_LINE_MAX` (default 128 bytes).

## Notes / limitations

- This port is currently focused on **Pico(2) W + lwIP**. Other RP2040/2350 network stacks are not covered.
- The encapsulated traffic leaves through the netif that was lwIP's default when `begin()` ran (the WiFi STA interface on Pico W). With several netifs, bring the right one up as default before `begin()`.
- WireGuard does not “connect” like TCP; the handshake typically starts when the stack needs to send traffic. Test by sending UDP/TCP traffic through the tunnel to an allowed destination.

## Files of interest (port layer)

- `src/wg_port_pico.h`, `src/wg_port_pico.cpp` – Pico W / lwIP compatibility layer (ESP-IDF replacements, IRQ-safe logger)
- `src/wireguard-platform.c` – platform init and helpers used by the core WireGuard implementation
- `src/wireguard_replay.h`, `src/wireguard_pbuf.h`, `src/wireguard_allowed_ip.h` – anti-replay window, contiguous `pbuf` helper and the AllowedIPs source check

## Tests

`extras/tests/host/run.sh` builds the helper headers above and the crypto primitives
against the lwIP sources bundled with the installed Arduino-Pico core and runs
their tests on the host (`g++`, no board needed; BLAKE2s, X25519 and
ChaCha20-Poly1305 are checked against known vectors). Set `LWIP_DIR` to use
another lwIP checkout.

`extras/tests/hardware/wg_services` is a sketch that exercises split and full tunnel,
the endpoint given as a name, WiFi loss under a tunnel and a soak across key
renewals against a Linux WireGuard endpoint; see `extras/tests/hardware/README.md`.

## License

See `LICENSE`. This port keeps the upstream license terms intact and adds a port attribution notice.
