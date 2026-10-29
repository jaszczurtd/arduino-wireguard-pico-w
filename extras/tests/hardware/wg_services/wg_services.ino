// Hardware test of arduino-wireguard-pico-w against a Linux WireGuard
// endpoint, modelled on the network services suite of JaszczurHAL.
//
// Host side (one Linux machine inside the WiFi LAN, see ../README.md):
//   - a WireGuard interface with the tunnel address TUNNEL_HOST_IP/24,
//     listening on WG_PORT, with this board as its peer
//     (AllowedIPs = WG_LOCAL_IP/32); creating it needs root;
//   - UDP echo on TUNNEL_HOST_IP:ECHO_UDP_PORT, TCP echo on all addresses
//     at ECHO_TCP_PORT (reached through the tunnel and on the LAN), an MQTT
//     broker on TUNNEL_HOST_IP:MQTT_PORT (only CONNECT/CONNACK is used).
//
// Every check prints "CHECK <name> pass=<0|1> ...", the soak prints "SOAK"
// lines every 30 s, and the run ends with "SUMMARY pass=<n> fail=<n>" followed
// by a STATUS line every 5 s. The checks, in order:
//   split tunnel, three cycles: handshake, UDP echo, TCP echo, MQTT CONNACK,
//     the LAN outside the tunnel, end() with a TCP connection still open;
//   full tunnel: handshake, UDP echo, TCP echo, end();
//   the endpoint given as a host name (WG_ENDPOINT_NAME, optional);
//   WiFi lost under an active tunnel, a new join, end() and a new tunnel;
//   soak of SOAK_SECONDS through the split tunnel: UDP echo every 100 ms and
//     one TCP echo connection kept open across the key renewals; passes with
//     at most 0.5 % failed exchanges and a free-heap drop of at most 8 KiB.
//
// Build flags: -DSOAK_SECONDS=<n> (default 300), -DWG_LOG_LEVEL=<0..5>.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiUdp.h>
#include <time.h>

#include "arduino-wireguard-pico-w.h"
#include "secrets.h"  // see secrets.h.example

#ifndef SOAK_SECONDS
#define SOAK_SECONDS 300
#endif

static const IPAddress WG_LOCAL_IP(10, 77, 0, 2);
static const IPAddress WG_ALLOWED_IP(10, 77, 0, 0);
static const IPAddress WG_ALLOWED_MASK(255, 255, 255, 0);
static const IPAddress TUNNEL_HOST_IP(10, 77, 0, 1);
static const uint16_t ECHO_UDP_PORT = 42045;
static const uint16_t ECHO_TCP_PORT = 42049;
static const uint16_t MQTT_PORT = 18883;
static const uint16_t LOCAL_UDP_PORT = 42046;

WireGuard wg;
WiFiUDP udp;

static int g_pass = 0;
static int g_fail = 0;
static bool led = false;

static void check(const char *name, bool ok, const char *detail = "") {
  if (ok) g_pass++; else g_fail++;
  Serial.printf("CHECK %s pass=%d %s\n", name, ok ? 1 : 0, detail);
}

static void pump(uint32_t ms) {
  const uint32_t t0 = millis();
  do {
    wg.loop();
    rp2040.wdt_reset();
    delay(1);
  } while (millis() - t0 < ms);
}

static bool time_synchro() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  const time_t MIN_VALID_EPOCH = 1672531200;  // 2023-01-01 UTC
  for (int i = 0; i < 60; i++) {
    if (time(nullptr) >= MIN_VALID_EPOCH) return true;
    pump(500);
  }
  return false;
}

static bool wifi_join(uint32_t budget_ms) {
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  const uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - t0 > budget_ms) return false;
    digitalWrite(LED_BUILTIN, (led = !led));
    pump(250);
  }
  return true;
}

static bool begin_split(const char *endpoint) {
  return wg.beginAdvanced(WG_LOCAL_IP, WG_PRIV, endpoint, WG_PEER_PUB, WG_PORT,
                          WG_ALLOWED_IP, WG_ALLOWED_MASK);
}

// Waits for peerUp() while kicking the handshake; ms to up or -1.
static long wait_up(uint32_t budget_ms) {
  const uint32_t t0 = millis();
  while (millis() - t0 < budget_ms) {
    if (wg.peerUp()) return (long)(millis() - t0);
    wg.kickHandshake(TUNNEL_HOST_IP, 9);
    pump(50);
  }
  return -1;
}

// One UDP echo exchange; true when the same payload comes back within wait_ms.
static bool udp_echo_once(uint32_t seq, uint32_t wait_ms) {
  char out[32];
  const int n = snprintf(out, sizeof(out), "wg-udp %lu", (unsigned long)seq);
  udp.beginPacket(TUNNEL_HOST_IP, ECHO_UDP_PORT);
  udp.write((const uint8_t *)out, (size_t)n);
  udp.endPacket();
  const uint32_t t0 = millis();
  while (millis() - t0 < wait_ms) {
    wg.loop();
    rp2040.wdt_reset();
    const int len = udp.parsePacket();
    if (len > 0) {
      char in[32] = {0};
      udp.read(in, sizeof(in) - 1);
      if (strncmp(in, out, (size_t)n) == 0) return true;
      // a late reply to an earlier datagram: keep waiting for ours
    }
    delay(1);
  }
  return false;
}

static int udp_echo(int count) {
  int ok = 0;
  for (int i = 0; i < count; i++) {
    if (udp_echo_once((uint32_t)i, 500)) ok++;
  }
  return ok;
}

// One TCP echo exchange on an open client.
static bool tcp_echo_once(WiFiClient &c, uint32_t seq, uint32_t wait_ms) {
  char out[32];
  const int n = snprintf(out, sizeof(out), "wg-tcp %lu\n", (unsigned long)seq);
  if (c.write((const uint8_t *)out, (size_t)n) != (size_t)n) return false;
  char in[32];
  int got = 0;
  const uint32_t t0 = millis();
  while (got < n && millis() - t0 < wait_ms) {
    wg.loop();
    rp2040.wdt_reset();
    const int r = c.read((uint8_t *)in + got, (size_t)(n - got));
    if (r > 0) got += r; else delay(1);
  }
  return got == n && memcmp(in, out, (size_t)n) == 0;
}

static int tcp_echo(const IPAddress &host, int count) {
  WiFiClient c;
  c.setTimeout(3000);
  if (!c.connect(host, ECHO_TCP_PORT)) return -1;
  int ok = 0;
  for (int i = 0; i < count; i++) {
    if (tcp_echo_once(c, (uint32_t)i, 2000)) ok++;
  }
  c.stop();
  return ok;
}

// MQTT 3.1.1 CONNECT with a clean session, expects CONNACK 0x20 0x02 0x00 0x00.
static bool mqtt_connack() {
  WiFiClient c;
  c.setTimeout(3000);
  if (!c.connect(TUNNEL_HOST_IP, MQTT_PORT)) return false;
  static const char client_id[] = "pico-wg";
  const uint8_t id_len = (uint8_t)(sizeof(client_id) - 1);
  uint8_t pkt[32];
  size_t p = 0;
  pkt[p++] = 0x10;                              // CONNECT
  pkt[p++] = (uint8_t)(10 + 2 + id_len);        // remaining length
  pkt[p++] = 0x00; pkt[p++] = 0x04;             // "MQTT"
  pkt[p++] = 'M'; pkt[p++] = 'Q'; pkt[p++] = 'T'; pkt[p++] = 'T';
  pkt[p++] = 0x04;                              // protocol level 4
  pkt[p++] = 0x02;                              // clean session
  pkt[p++] = 0x00; pkt[p++] = 30;               // keep alive 30 s
  pkt[p++] = 0x00; pkt[p++] = id_len;
  memcpy(pkt + p, client_id, id_len);
  p += id_len;
  if (c.write(pkt, p) != p) { c.stop(); return false; }
  uint8_t ack[4] = {0};
  int got = 0;
  const uint32_t t0 = millis();
  while (got < 4 && millis() - t0 < 3000) {
    wg.loop();
    rp2040.wdt_reset();
    const int r = c.read(ack + got, (size_t)(4 - got));
    if (r > 0) got += r; else delay(1);
  }
  const bool ok = got == 4 && ack[0] == 0x20 && ack[1] == 0x02 && ack[3] == 0x00;
  const uint8_t disconnect[2] = {0xE0, 0x00};
  c.write(disconnect, sizeof(disconnect));
  c.stop();
  return ok;
}

static void split_cycle(int n) {
  char name[32];
  char detail[64];
  const uint32_t t0 = millis();
  const bool ok = begin_split(WG_ENDPOINT);
  const long up = ok ? wait_up(10000) : -1;
  snprintf(name, sizeof(name), "split%d_handshake", n);
  snprintf(detail, sizeof(detail), "begin=%d up_ms=%ld", ok ? 1 : 0, up);
  check(name, up >= 0, detail);
  if (up < 0) { wg.end(); return; }
  (void)t0;

  const int u = udp_echo(20);
  snprintf(name, sizeof(name), "split%d_udp_echo", n);
  snprintf(detail, sizeof(detail), "rx=%d/20", u);
  check(name, u == 20, detail);

  const int t = tcp_echo(TUNNEL_HOST_IP, 20);
  snprintf(name, sizeof(name), "split%d_tcp_echo", n);
  snprintf(detail, sizeof(detail), "rx=%d/20", t);
  check(name, t == 20, detail);

  snprintf(name, sizeof(name), "split%d_mqtt_connack", n);
  check(name, mqtt_connack());

  IPAddress lan;
  const bool lan_ok = lan.fromString(HOST_LAN_IP);
  const int l = lan_ok ? tcp_echo(lan, 5) : -1;
  snprintf(name, sizeof(name), "split%d_lan_outside", n);
  snprintf(detail, sizeof(detail), "host=%s rx=%d/5", HOST_LAN_IP, l);
  check(name, l == 5, detail);

  // end() with a TCP connection still open through the tunnel.
  WiFiClient open;
  open.setTimeout(3000);
  const bool connected = open.connect(TUNNEL_HOST_IP, ECHO_TCP_PORT) && tcp_echo_once(open, 99, 2000);
  wg.end();
  bool dropped = false;
  const uint32_t t1 = millis();
  while (millis() - t1 < 3000) {
    if (!open.connected()) { dropped = true; break; }
    pump(20);
  }
  open.stop();
  snprintf(name, sizeof(name), "split%d_end_with_open_tcp", n);
  snprintf(detail, sizeof(detail), "connected=%d dropped_after_end=%d init=%d", connected ? 1 : 0,
           dropped ? 1 : 0, wg.is_initialized() ? 1 : 0);
  check(name, connected && dropped && !wg.is_initialized(), detail);
  pump(500);
}

static void full_tunnel() {
  char detail[64];
  const bool ok = wg.begin(WG_LOCAL_IP, WG_PRIV, WG_ENDPOINT, WG_PEER_PUB, WG_PORT);
  const long up = ok ? wait_up(10000) : -1;
  snprintf(detail, sizeof(detail), "begin=%d up_ms=%ld", ok ? 1 : 0, up);
  check("full_handshake", up >= 0, detail);
  if (up >= 0) {
    const int u = udp_echo(20);
    snprintf(detail, sizeof(detail), "rx=%d/20", u);
    check("full_udp_echo", u == 20, detail);
    const int t = tcp_echo(TUNNEL_HOST_IP, 20);
    snprintf(detail, sizeof(detail), "rx=%d/20", t);
    check("full_tcp_echo", t == 20, detail);
  }
  wg.end();
  check("full_end", !wg.is_initialized());
  pump(500);
}

static void endpoint_by_name() {
#if defined(WG_ENDPOINT_NAME)
  char detail[96];
  const uint32_t t0 = millis();
  const bool ok = begin_split(WG_ENDPOINT_NAME);
  const uint32_t begin_ms = millis() - t0;
  const long up = ok ? wait_up(10000) : -1;
  snprintf(detail, sizeof(detail), "name=%s begin=%d begin_ms=%lu up_ms=%ld", WG_ENDPOINT_NAME,
           ok ? 1 : 0, (unsigned long)begin_ms, up);
  check("name_handshake", up >= 0, detail);
  if (up >= 0) {
    const int u = udp_echo(10);
    snprintf(detail, sizeof(detail), "rx=%d/10", u);
    check("name_udp_echo", u == 10, detail);
  }
  wg.end();
  pump(500);
#else
  Serial.println("CHECK name_handshake pass=skip (WG_ENDPOINT_NAME not set)");
#endif
}

// Loses WiFi under an active tunnel, joins again and starts a new tunnel.
// Leaves the new tunnel up for the soak.
static void wifi_loss() {
  char detail[64];
  const bool ok = begin_split(WG_ENDPOINT);
  const long up = ok ? wait_up(10000) : -1;
  snprintf(detail, sizeof(detail), "begin=%d up_ms=%ld", ok ? 1 : 0, up);
  check("wifi_loss_tunnel_before", up >= 0, detail);

  WiFi.disconnect();
  const uint32_t t0 = millis();
  while (WiFi.status() == WL_CONNECTED && millis() - t0 < 5000) pump(100);
  const bool lost = WiFi.status() != WL_CONNECTED;
  pump(1000);
  const bool joined = wifi_join(30000);
  snprintf(detail, sizeof(detail), "lost=%d rejoined=%d ip=%s", lost ? 1 : 0, joined ? 1 : 0,
           WiFi.localIP().toString().c_str());
  check("wifi_loss_rejoin", lost && joined, detail);

  wg.end();
  const bool ok2 = begin_split(WG_ENDPOINT);
  const long up2 = ok2 ? wait_up(10000) : -1;
  const int u = up2 >= 0 ? udp_echo(10) : -1;
  snprintf(detail, sizeof(detail), "begin=%d up_ms=%ld udp_rx=%d/10", ok2 ? 1 : 0, up2, u);
  check("wifi_loss_new_tunnel", up2 >= 0 && u == 10, detail);
}

static void soak() {
  if (!wg.is_initialized() || !wg.peerUp()) {
    check("soak", false, "no tunnel");
    return;
  }
  const uint32_t heap_start = rp2040.getFreeHeap();
  uint32_t heap_min = heap_start;
  uint32_t udp_ok = 0, udp_fail = 0, tcp_ok = 0, tcp_fail = 0, tcp_reconnects = 0;
  WiFiClient tcp;
  tcp.setTimeout(3000);
  bool tcp_up = tcp.connect(TUNNEL_HOST_IP, ECHO_TCP_PORT);
  if (!tcp_up) tcp_reconnects++;

  const uint32_t t0 = millis();
  uint32_t last_report = t0;
  uint32_t seq = 0;
  while (millis() - t0 < (uint32_t)SOAK_SECONDS * 1000u) {
    if (udp_echo_once(seq, 300)) udp_ok++; else udp_fail++;
    if (!tcp_up) {
      tcp.stop();
      tcp_up = tcp.connect(TUNNEL_HOST_IP, ECHO_TCP_PORT);
      if (!tcp_up) { tcp_fail++; pump(200); }
      else tcp_reconnects++;
    }
    if (tcp_up) {
      if (tcp_echo_once(tcp, seq, 1000)) tcp_ok++;
      else { tcp_fail++; tcp_up = false; }
    }
    seq++;
    const uint32_t heap = rp2040.getFreeHeap();
    if (heap < heap_min) heap_min = heap;
    if (millis() - last_report >= 30000) {
      last_report = millis();
      digitalWrite(LED_BUILTIN, (led = !led));
      Serial.printf("SOAK t=%lu udp_ok=%lu udp_fail=%lu tcp_ok=%lu tcp_fail=%lu tcp_reconnects=%lu heap=%lu\n",
                    (unsigned long)((millis() - t0) / 1000u), (unsigned long)udp_ok, (unsigned long)udp_fail,
                    (unsigned long)tcp_ok, (unsigned long)tcp_fail, (unsigned long)tcp_reconnects,
                    (unsigned long)heap);
    }
    pump(100);
  }
  tcp.stop();
  const uint32_t total = udp_ok + udp_fail + tcp_ok + tcp_fail;
  const uint32_t failed = udp_fail + tcp_fail;
  const bool loss_ok = total > 0 && failed * 1000u <= total * 5u;  // <= 0.5 %
  const uint32_t heap_end = rp2040.getFreeHeap();
  const bool heap_ok = heap_start - heap_end <= 8192u || heap_end >= heap_start;
  char detail[160];
  snprintf(detail, sizeof(detail),
           "seconds=%d udp_ok=%lu udp_fail=%lu tcp_ok=%lu tcp_fail=%lu tcp_reconnects=%lu heap_start=%lu heap_end=%lu heap_min=%lu",
           SOAK_SECONDS, (unsigned long)udp_ok, (unsigned long)udp_fail, (unsigned long)tcp_ok,
           (unsigned long)tcp_fail, (unsigned long)tcp_reconnects, (unsigned long)heap_start,
           (unsigned long)heap_end, (unsigned long)heap_min);
  check("soak", loss_ok && heap_ok && tcp_reconnects <= 1, detail);
}

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  rp2040.wdt_begin(8000);
  Serial.begin(115200);
  const uint32_t t0 = millis();
  while (!Serial && millis() - t0 < 5000) {
    rp2040.wdt_reset();
    delay(10);
  }
  Serial.printf("WG_SERVICES soak_seconds=%d\n", SOAK_SECONDS);

  check("wifi_join", wifi_join(60000), WiFi.localIP().toString().c_str());
  check("ntp", time_synchro());
  udp.begin(LOCAL_UDP_PORT);

  for (int n = 1; n <= 3; n++) split_cycle(n);
  full_tunnel();
  endpoint_by_name();
  wifi_loss();
  soak();

  Serial.printf("SUMMARY pass=%d fail=%d\n", g_pass, g_fail);
}

void loop() {
  static uint32_t last_report = 0;
  rp2040.wdt_reset();
  wg.loop();
  if (millis() - last_report >= 5000) {
    last_report = millis();
    digitalWrite(LED_BUILTIN, (led = !led));
    Serial.printf("STATUS up=%d heap=%lu\n", wg.peerUp() ? 1 : 0, (unsigned long)rp2040.getFreeHeap());
  }
  delay(10);
}
