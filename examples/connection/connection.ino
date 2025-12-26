#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
#include <hardware/watchdog.h>

#include "arduino-wireguard-pico-w.h"
#include "WireguardTests.h"


// ---- WiFi credentials ----
static const char* WIFI_SSID = "WIFI-SSID";
static const char* WIFI_PASSWORD = "WIFI-PASSWD";

// ---- WireGuard configuration ----
// Address assigned to this Pico W inside the WireGuard VPN.
static const IPAddress WG_LOCAL_IP(10, 8, 0, 9);

// This Pico-W device private key (base64).
static const char* WG_PRIVATE_KEY = "private key here";

// Wireguard server's public key (base64).
static const char* WG_SERVER_PUBLIC_KEY = "public key here";

// Wireguard server endpoint . Use an IPv4 string/Hostname.
static const char* WG_ENDPOINT = "wireguard IP address";

// Server listen port (as configured on wireguard server).
static const uint16_t WG_ENDPOINT_PORT = 51820;

// Allowed IPs routed through the tunnel.
// Typical setup: route only the VPN subnet (e.g. 10.8.0.0/24). Adjust to your WG subnet.
static const IPAddress WG_ALLOWED_IP(10, 8, 0, 0);
static const IPAddress WG_ALLOWED_MASK(255, 255, 255, 0);

static constexpr const uint32_t UPDATE_INTERVAL_MS = 1500;

WireGuard wg;
bool alertBlink = false;

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
  delay(3000);  // wait for Serial
  
  Serial.println("=== WireGuard Pico W Debug ===");
  
  // 1. WiFi test
  Serial.println("1. WiFi connection...");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
      delay(500);
      Serial.print(".");
  }
  Serial.printf("\nWiFi OK. IP: %s\n", WiFi.localIP().toString().c_str());
  
  // 2. Test NTP
  Serial.println("2. NTP time synchro...");

  char buftime[32];
  if(time_synchro("CET-1CEST,M3.5.0/2,M10.5.0/3", buftime, sizeof(buftime))) {
    Serial.printf("time: %s\n", buftime);    
  } else {
    Serial.printf("NTP sync failed. check WiFi/DNS/UDP 123.\n");
  }
  
  // 3. Test random
  test_wireguard_random();
  // 4. Test crypto
  test_crypto_primitives();

  watchdog_enable(4000, 1);
  test_udp_send();

  // 5. WireGuard init
  Serial.println("5. Starting WireGuard...\n");

  // Route only WG_ALLOWED_IP/WG_ALLOWED_MASK through the tunnel.
  // If you want full-tunnel, use wg.begin(...) instead.

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

  Serial.println("WireGuard initialized.");
}

void loop() {
  watchdog_update();
  digitalWrite(LED_BUILTIN, (alertBlink = !alertBlink));

  delay(UPDATE_INTERVAL_MS);
}
