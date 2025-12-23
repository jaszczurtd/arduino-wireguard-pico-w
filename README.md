# WireGuard-ESP32 (Raspberry Pi Pico W / RP2040 port)

This library is a **port** of the original **WireGuard-ESP32** project to **Raspberry Pi Pico W (RP2040 + CYW43)** using the **Arduino-Pico (Earle Philhower) core** and **lwIP**.

The goal of the port is to keep the original API as intact as possible, while replacing ESP-IDF / ESP32-specific dependencies with a small Pico W compatibility layer.

## Credits

- Original project / API: the WireGuard-ESP32 library and its upstream dependencies (see `LICENSE`).
- Pico W / RP2040 port: **Marcin Kielesiński** (this repository).

## What changed in this port (high level)

The original library targets ESP32 and depends on ESP-IDF pieces. For Pico W (Arduino-Pico + lwIP) this port replaces or adapts the following:

- **ESP logging** (`ESP_LOGx`) replaced with lightweight stubs / optional `Serial` logging.
- **`tcpip_adapter_*`** (ESP-IDF networking glue) replaced with a Pico/lwIP shim.
- **Netif lookup** simplified: on Pico W the STA interface maps to **lwIP's default netif** (`netif_default`).
- **Platform glue** moved into `src/wg_port_pico.h` and `src/wireguard-platform.c`.
- **Build fixes** for ARM GCC (RP2040 toolchain), including a warning fix in `x25519.c` (treat `a24` as an 8-limb field element to avoid false-positive overread warnings).

## Requirements

- Raspberry Pi Pico W (RP2040)
- Arduino IDE / Arduino CLI
- Arduino-Pico core (Earle Philhower), board: `rp2040:rp2040:rpipicow`
- WiFi enabled (CYW43)
- IPv4 networking (WireGuard endpoint by IP is supported)

## Usage (example)

```cpp
#include <WiFi.h>
#include <WireGuard-ESP32.h>

WireGuard wg;

static const char* WIFI_SSID = "your-ssid";
static const char* WIFI_PASS = "your-pass";

// WireGuard keys (base64 strings, like in wg-quick)
static const char* WG_PRIVATE_KEY = "YOUR_PRIVATE_KEY_BASE64";
static const char* WG_PEER_PUBLIC_KEY = "SERVER_PUBLIC_KEY_BASE64";

// Example configuration:
// - local tunnel address: 10.8.0.50
// - endpoint: 203.0.113.10:10000
// - allowed IPs: 0.0.0.0/0 (full tunnel) or only your LAN/VPN ranges
static const IPAddress WG_LOCAL_IP(10, 8, 0, 50);
static const IPAddress WG_LOCAL_GW(0, 0, 0, 0);
static const IPAddress WG_LOCAL_MASK(255, 255, 255, 0);

static const IPAddress WG_ENDPOINT_IP(203, 0, 113, 10);
static const uint16_t  WG_ENDPOINT_PORT = 10000;

static const IPAddress WG_ALLOWED_IP(0, 0, 0, 0);
static const IPAddress WG_ALLOWED_MASK(0, 0, 0, 0);

void setup() {
  Serial.begin(115200);

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(250);
  }

  // beginAdvanced(local_ip, private_key, peer_public_key, preshared_key (optional),
  //               endpoint_port, endpoint_ip, allowed_ip, allowed_mask)
  wg.beginAdvanced(WG_LOCAL_IP,
                   WG_PRIVATE_KEY,
                   WG_PEER_PUBLIC_KEY,
                   nullptr,                 // preshared key (optional)
                   WG_ENDPOINT_PORT,
                   WG_ENDPOINT_IP,
                   WG_ALLOWED_IP,
                   WG_ALLOWED_MASK);

  // From this point the tunnel should attempt a handshake when traffic is sent.
}

void loop() {
  // Your application code here.
}
```

## Notes / limitations

- This port is currently focused on **Pico W + lwIP**. Other RP2040 network stacks are not covered.
- The netif mapping assumes a **single active WiFi STA interface** (typical for Pico W).
- If you run multiple netifs or unusual routing, you may need to adjust the `tcpip_adapter_get_netif()` shim.
- WireGuard does not “connect” like TCP; the handshake typically starts when the stack needs to send traffic. Test by sending UDP/TCP traffic through the tunnel to an allowed destination.

## Files of interest (port layer)

- `src/wg_port_pico.h` – Pico W / lwIP compatibility glue (ESP-IDF replacements)
- `src/wireguard-platform.c` – platform init and helpers used by the core WireGuard implementation

## License

See `LICENSE`. This port keeps the upstream license terms intact and adds a port attribution notice.
