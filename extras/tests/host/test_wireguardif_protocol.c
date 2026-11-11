// Two real WireGuard engines of the library, a client and a server, on the
// real lwIP core (IPv4, UDP, timers). Their UDP datagrams are captured on a
// shared "wire" netif and handed to the other engine with a chosen source
// address, so a test can replay or forge messages the way an observer of the
// traffic could (GHSA-7grw-r329-8g8c of wireguard-lwip).
//
// wireguardif.c is compiled into this file so the test can run the engine's
// periodic service (the static wireguardif_tmr()) at a chosen time instead of
// waiting for its lwIP timer.

#include "../../../src/wireguardif.c"

#include "lwip/init.h"
#include "lwip/stats.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>

// ---- minimal test runner ---------------------------------------------------

static jmp_buf s_abort_test;
static const char *s_test_name;
static int s_tests_run;
static int s_tests_failed;

static void fail_test(const char *file, int line, const char *format, ...) {
  va_list args;
  fprintf(stderr, "%s:%d: %s: ", file, line, s_test_name);
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fputc('\n', stderr);
  longjmp(s_abort_test, 1);
}

#define TEST_ASSERT_TRUE(condition)                                            \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fail_test(__FILE__, __LINE__, "expected true: %s", #condition);         \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_FALSE(condition)                                           \
  do {                                                                         \
    if (condition) {                                                           \
      fail_test(__FILE__, __LINE__, "expected false: %s", #condition);        \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_NOT_NULL(pointer) TEST_ASSERT_TRUE((pointer) != NULL)

#define TEST_ASSERT_EQUAL(expected, actual)                                    \
  do {                                                                         \
    const long long expected_ = (long long)(expected);                         \
    const long long actual_ = (long long)(actual);                             \
    if (expected_ != actual_) {                                                \
      fail_test(__FILE__, __LINE__, "%s: expected %lld, got %lld", #actual,    \
                expected_, actual_);                                           \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_EQUAL_MEMORY(expected, actual, length)                     \
  do {                                                                         \
    if (memcmp((expected), (actual), (length)) != 0) {                         \
      fail_test(__FILE__, __LINE__, "%s differs from %s", #actual, #expected); \
    }                                                                          \
  } while (0)

static void setUp(void);
static void tearDown(void);

static void run_test(void (*test)(void), const char *name) {
  s_test_name = name;
  ++s_tests_run;
  setUp();
  if (setjmp(s_abort_test) == 0) {
    test();
  } else {
    ++s_tests_failed;
  }
  tearDown();
}

#define RUN_TEST(test) run_test(test, #test)

// ---- platform hooks of the engine, driven by the test clock -----------------

enum {
  kMaxDatagrams = 32,
  kMaxDatagramBytes = 256,
  kUdpOverhead = 20 + 8, // IPv4 header without options and UDP header
  kClientPort = 40000,
  kServerPort = 51820,
  kAttackerPort = 4444,
};

typedef struct {
  ip_addr_t destination;
  u16_t destination_port;
  size_t length;
  uint8_t data[kMaxDatagramBytes];
} datagram_t;

static uint32_t s_now_ms;
static uint32_t s_random_state;
static datagram_t s_sent[kMaxDatagrams];
static size_t s_sent_count;
static bool s_sent_overflow;

static struct netif s_wire;
static struct netif s_client;
static struct netif s_server;
static struct wireguardif_init_data s_client_init;
static struct wireguardif_init_data s_server_init;

static ip_addr_t s_client_address;   // 192.0.2.10
static ip_addr_t s_rebound_address;  // 192.0.2.11, the client after NAT rebind
static ip_addr_t s_server_address;   // 192.0.2.20
static ip_addr_t s_attacker_address; // 198.51.100.66

// 32 bytes of 0x01 and of 0x02 in base64; the engine clamps the scalars.
static const char kClientPrivateKey[] =
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
static const char kServerPrivateKey[] =
    "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

u32_t sys_now(void) { return s_now_ms; }

uint32_t wireguard_sys_now(void) { return s_now_ms; }

void wireguard_random_bytes(void *bytes, size_t size) {
  uint8_t *out = (uint8_t *)bytes;
  for (size_t index = 0u; index < size; ++index) {
    s_random_state = s_random_state * 1664525u + 1013904223u;
    out[index] = (uint8_t)(s_random_state >> 24u);
  }
}

// TAI64N of 2020-01-01 plus the test clock, so later messages carry later
// timestamps.
static void tai64n_at(uint32_t now_ms, uint8_t output[WIREGUARD_TAI64N_LEN]) {
  const uint64_t seconds =
      UINT64_C(0x400000000000000a) + UINT64_C(1577836800) + now_ms / 1000u;
  const uint32_t nanos = (now_ms % 1000u) * 1000000u;
  U64TO8_BIG(output, seconds);
  U32TO8_BIG(output + 8, nanos);
}

void wireguard_tai64n_now(uint8_t *output) { tai64n_at(s_now_ms, output); }

bool wireguard_is_under_load(void) { return false; }

// The engine logs warnings and errors; the expected ones (bad handshakes and
// the like) are not printed.
void wg_logf_(char lvl, const char *fmt, ...) {
  (void)lvl;
  (void)fmt;
}

// ---- the wire and the two engines ------------------------------------------

// Everything the engines send goes out here: an IPv4 header, a UDP header
// and the WireGuard message.
static err_t wire_output(struct netif *netif, struct pbuf *p,
                         const ip4_addr_t *destination) {
  (void)netif;
  uint8_t headers[kUdpOverhead];
  if ((s_sent_count >= kMaxDatagrams) || (p->tot_len < kUdpOverhead) ||
      ((size_t)(p->tot_len - kUdpOverhead) > kMaxDatagramBytes)) {
    s_sent_overflow = true;
    return ERR_OK;
  }
  datagram_t *sent = &s_sent[s_sent_count++];
  pbuf_copy_partial(p, headers, sizeof(headers), 0u);
  ip_addr_copy_from_ip4(sent->destination, *destination);
  sent->destination_port = (u16_t)((headers[22] << 8) | headers[23]);
  sent->length = (size_t)(p->tot_len - kUdpOverhead);
  pbuf_copy_partial(p, sent->data, (u16_t)sent->length, kUdpOverhead);
  return ERR_OK;
}

static err_t wire_init(struct netif *netif) {
  netif->name[0] = 'w';
  netif->name[1] = 'r';
  netif->output = wire_output;
  netif->mtu = 1500u;
  return ERR_OK;
}

static struct wireguard_device *device_of(struct netif *netif) {
  return (struct wireguard_device *)netif->state;
}

static struct wireguard_peer *peer_of(struct netif *netif) {
  return &device_of(netif)->peers[0];
}

// The engine's periodic service (handshake, keep-alive, key lifetimes), run
// now. The engine reschedules its own timer, so the pending one is removed
// first.
static void service(struct netif *netif) {
  struct wireguard_device *device = device_of(netif);
  sys_untimeout(wireguardif_tmr, device);
  wireguardif_tmr(device);
}

static uint8_t message_type(const datagram_t *datagram) {
  return wireguard_get_message_type(datagram->data, datagram->length);
}

// The only datagram sent since 'first'.
static const datagram_t *sent_once_since(size_t first) {
  TEST_ASSERT_FALSE(s_sent_overflow);
  TEST_ASSERT_EQUAL(first + 1u, s_sent_count);
  return &s_sent[first];
}

static void deliver(struct netif *to, const datagram_t *datagram,
                    const ip_addr_t *from, u16_t from_port) {
  struct pbuf *p =
      pbuf_alloc(PBUF_TRANSPORT, (u16_t)datagram->length, PBUF_RAM);
  TEST_ASSERT_NOT_NULL(p);
  TEST_ASSERT_EQUAL(ERR_OK,
                    pbuf_take(p, datagram->data, (u16_t)datagram->length));
  wireguardif_network_rx(device_of(to), device_of(to)->udp_pcb, p, from,
                         from_port);
}

static void encode_public_key(struct netif *netif, char *out, size_t size) {
  size_t length = size;
  TEST_ASSERT_TRUE(wireguard_base64_encode(
      device_of(netif)->public_key, WIREGUARD_PUBLIC_KEY_LEN, out, &length));
}

static void start_node(struct netif *netif, struct wireguardif_init_data *init,
                       const char *private_key, u16_t listen_port,
                       uint8_t tunnel_host) {
  ip4_addr_t address;
  ip4_addr_t netmask;
  ip4_addr_t gateway;
  IP4_ADDR(&address, 10, 8, 0, tunnel_host);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 0, 0, 0, 0);
  memset(netif, 0, sizeof(*netif));
  memset(init, 0, sizeof(*init));
  init->private_key = private_key;
  init->listen_port = listen_port;
  init->bind_netif = &s_wire;
  TEST_ASSERT_NOT_NULL(netif_add(netif, &address, &netmask, &gateway, init,
                                 wireguardif_init, ip_input));
  netif_set_up(netif);
}

static void add_peer(struct netif *netif, const char *public_key,
                     const ip_addr_t *endpoint, u16_t endpoint_port,
                     uint8_t allowed_host, uint8_t allowed_prefix_byte,
                     const uint8_t *greatest_timestamp) {
  struct wireguardif_peer peer;
  u8_t index = WIREGUARDIF_INVALID_INDEX;
  memset(&peer, 0, sizeof(peer));
  peer.public_key = public_key;
  IP_ADDR4(&peer.allowed_ip, 10, 8, 0, allowed_host);
  IP_ADDR4(&peer.allowed_mask, 255, 255, 255, allowed_prefix_byte);
  if (endpoint != NULL) {
    peer.endpoint_ip = *endpoint;
    peer.endport_port = endpoint_port;
  }
  peer.keep_alive = 0u; // no keep-alive traffic of its own in these tests
  if (greatest_timestamp != NULL) {
    memcpy(peer.greatest_timestamp, greatest_timestamp,
           sizeof(peer.greatest_timestamp));
  }
  TEST_ASSERT_EQUAL(ERR_OK, wireguardif_add_peer(netif, &peer, &index));
  TEST_ASSERT_EQUAL(0u, index);
}

static void stop_node(struct netif *netif) {
  if (netif->state != NULL) {
    netif_remove(netif);
    (void)wireguardif_remove_peer(netif, 0u);
    wireguardif_shutdown(netif);
  }
}

static char s_client_public_key[64];
static char s_server_public_key[64];

// The server, with or without the client's configured endpoint, and the
// client, configured to connect to the server.
static void start_pair(bool server_knows_client_endpoint) {
  start_node(&s_client, &s_client_init, kClientPrivateKey, kClientPort, 2u);
  start_node(&s_server, &s_server_init, kServerPrivateKey, kServerPort, 1u);
  encode_public_key(&s_client, s_client_public_key,
                    sizeof(s_client_public_key));
  encode_public_key(&s_server, s_server_public_key,
                    sizeof(s_server_public_key));
  add_peer(&s_client, s_server_public_key, &s_server_address, kServerPort, 0u,
           0u, NULL);
  add_peer(&s_server, s_client_public_key,
           server_knows_client_endpoint ? &s_client_address : NULL,
           server_knows_client_endpoint ? kClientPort : 0u, 2u, 255u, NULL);
  TEST_ASSERT_EQUAL(ERR_OK, wireguardif_connect(&s_client, 0u));
}

// The client's next initiation, as it went out on the wire.
static datagram_t client_initiation(void) {
  const size_t first = s_sent_count;
  service(&s_client);
  const datagram_t *initiation = sent_once_since(first);
  TEST_ASSERT_EQUAL(MESSAGE_HANDSHAKE_INITIATION, message_type(initiation));
  return *initiation;
}

// A handshake initiation of 'from' to its peer, made directly instead of by
// its timer, the way an observer could capture it. It becomes the pending
// initiation of 'from'.
static datagram_t initiation_of(struct netif *from) {
  struct message_handshake_initiation message;
  datagram_t datagram;
  TEST_ASSERT_TRUE(wireguard_create_handshake_initiation(
      device_of(from), peer_of(from), &message));
  memset(&datagram, 0, sizeof(datagram));
  memcpy(datagram.data, &message, sizeof(message));
  datagram.length = sizeof(message);
  return datagram;
}

// The only datagram sent since 'first' is a handshake response to 'address'.
static datagram_t response_to(size_t first, const ip_addr_t *address,
                              u16_t port) {
  const datagram_t response = *sent_once_since(first);
  TEST_ASSERT_EQUAL(MESSAGE_HANDSHAKE_RESPONSE, message_type(&response));
  TEST_ASSERT_TRUE(ip_addr_cmp(&response.destination, address));
  TEST_ASSERT_EQUAL(port, response.destination_port);
  return response;
}

// A full handshake with the client behind 'client_address'. The response
// goes back to that address; the endpoint follows the keep-alive. Returns the
// keep-alive that completed it on the server.
static datagram_t handshake_from(const ip_addr_t *client_address,
                                 u16_t client_port) {
  const datagram_t initiation = client_initiation();
  size_t first = s_sent_count;
  deliver(&s_server, &initiation, client_address, client_port);
  const datagram_t response = response_to(first, client_address, client_port);

  first = s_sent_count;
  deliver(&s_client, &response, &s_server_address, kServerPort);
  const datagram_t keepalive = *sent_once_since(first);
  TEST_ASSERT_EQUAL(MESSAGE_TRANSPORT_DATA, message_type(&keepalive));
  deliver(&s_server, &keepalive, client_address, client_port);
  TEST_ASSERT_TRUE(peer_of(&s_server)->curr_keypair.valid);
  return keepalive;
}

// An inner IPv4 packet from tunnel address 10.8.0.'source_host' to
// 10.8.0.'destination_host', sent through the WireGuard interface 'from'.
static datagram_t sends_inner_packet(struct netif *from, uint8_t source_host,
                                     uint8_t destination_host) {
  uint8_t packet[28] = {
      0x45u, 0u, 0u,  28u, 0u, 1u,          0u,  0u, 64u, 253u,
      0u,    0u, 10u, 8u,  0u, source_host, 10u, 8u, 0u,  destination_host};
  ip4_addr_t destination;
  struct pbuf *p = pbuf_alloc(PBUF_RAW, sizeof(packet), PBUF_RAM);
  TEST_ASSERT_NOT_NULL(p);
  TEST_ASSERT_EQUAL(ERR_OK, pbuf_take(p, packet, sizeof(packet)));
  IP4_ADDR(&destination, 10, 8, 0, destination_host);
  const size_t first = s_sent_count;
  TEST_ASSERT_EQUAL(ERR_OK, from->output(from, p, &destination));
  pbuf_free(p);
  const datagram_t *sent = sent_once_since(first);
  TEST_ASSERT_EQUAL(MESSAGE_TRANSPORT_DATA, message_type(sent));
  return *sent;
}

static datagram_t client_sends_inner_packet(void) {
  return sends_inner_packet(&s_client, 2u, 1u);
}

// A transport message with an arbitrary plaintext under the client's current
// session keys, as only a holder of those keys can make it.
static datagram_t client_transport_with_plaintext(const uint8_t *plaintext,
                                                  size_t length) {
  struct wireguard_keypair *keypair = &peer_of(&s_client)->curr_keypair;
  datagram_t datagram;
  struct message_transport_data *header =
      (struct message_transport_data *)datagram.data;
  TEST_ASSERT_TRUE(keypair->valid);
  TEST_ASSERT_TRUE(sizeof(struct message_transport_data) + length +
                       WIREGUARD_AUTHTAG_LEN <=
                   sizeof(datagram.data));
  memset(&datagram, 0, sizeof(datagram));
  header->type = MESSAGE_TRANSPORT_DATA;
  header->receiver = keypair->remote_index;
  U64TO8_LITTLE(header->counter, keypair->sending_counter);
  wireguard_encrypt_packet(header->enc_packet, plaintext, length, keypair);
  datagram.length =
      sizeof(struct message_transport_data) + length + WIREGUARD_AUTHTAG_LEN;
  return datagram;
}

static void assert_endpoint(struct netif *netif, const ip_addr_t *address,
                            u16_t port) {
  TEST_ASSERT_TRUE(ip_addr_cmp(&peer_of(netif)->ip, address));
  TEST_ASSERT_EQUAL(port, peer_of(netif)->port);
}

static size_t responses_since(size_t first) {
  size_t responses = 0u;
  for (size_t index = first; index < s_sent_count; ++index) {
    if (message_type(&s_sent[index]) == MESSAGE_HANDSHAKE_RESPONSE) {
      ++responses;
    }
  }
  return responses;
}

static bool all_zero(const void *data, size_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  for (size_t index = 0u; index < size; ++index) {
    if (bytes[index] != 0u) {
      return false;
    }
  }
  return true;
}

static void setUp(void) {
  ip4_addr_t address;
  ip4_addr_t netmask;
  ip4_addr_t gateway;
  s_now_ms = 1000u;
  s_random_state = 0x2545f491u;
  s_sent_count = 0u;
  s_sent_overflow = false;
  memset(&s_client, 0, sizeof(s_client));
  memset(&s_server, 0, sizeof(s_server));
  IP_ADDR4(&s_client_address, 192, 0, 2, 10);
  IP_ADDR4(&s_rebound_address, 192, 0, 2, 11);
  IP_ADDR4(&s_server_address, 192, 0, 2, 20);
  IP_ADDR4(&s_attacker_address, 198, 51, 100, 66);
  IP4_ADDR(&address, 192, 0, 2, 1);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 0, 0, 0, 0);
  memset(&s_wire, 0, sizeof(s_wire));
  if (netif_add(&s_wire, &address, &netmask, &gateway, NULL, wire_init,
                NULL) == NULL) {
    fprintf(stderr, "setUp: netif_add of the wire failed\n");
    exit(2);
  }
  netif_set_up(&s_wire);
  netif_set_link_up(&s_wire);
}

static void tearDown(void) {
  stop_node(&s_client);
  stop_node(&s_server);
  netif_remove(&s_wire);
}

// ---- tests -------------------------------------------------------------------

// Issue 1: the endpoint moved before the replay check, and keep-alives were
// never checked, so a captured packet resent from anywhere redirected the
// tunnel.
static void test_replayed_transport_packets_do_not_move_the_endpoint(void) {
  start_pair(false);
  const datagram_t keepalive = handshake_from(&s_client_address, kClientPort);
  const datagram_t data = client_sends_inner_packet();
  const u32_t received_before = lwip_stats.ip.recv;

  deliver(&s_server, &data, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(received_before + 1u, lwip_stats.ip.recv);
  const uint32_t last_rx = peer_of(&s_server)->last_rx;

  s_now_ms += 1000u;
  deliver(&s_server, &data, &s_attacker_address, kAttackerPort);
  deliver(&s_server, &keepalive, &s_attacker_address, kAttackerPort);

  assert_endpoint(&s_server, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(received_before + 1u, lwip_stats.ip.recv);
  TEST_ASSERT_EQUAL(last_rx, peer_of(&s_server)->last_rx);

  // A new packet from a new address still roams the endpoint.
  const datagram_t roamed = client_sends_inner_packet();
  deliver(&s_server, &roamed, &s_rebound_address, kClientPort + 1u);
  assert_endpoint(&s_server, &s_rebound_address, kClientPort + 1u);
  TEST_ASSERT_EQUAL(received_before + 2u, lwip_stats.ip.recv);
}

// Issue 2: a cookie reply is keyed by the responder's public key and the
// initiation's mac1, which travels in clear, so anyone who saw the initiation
// and knows that key can make a valid one. The server's precomputed cookie
// key stands in for such an attacker; the reply must only store the cookie.
static void test_a_valid_cookie_reply_does_not_move_the_endpoint(void) {
  start_pair(false);
  const datagram_t initiation = client_initiation();
  const struct message_handshake_initiation *message =
      (const struct message_handshake_initiation *)initiation.data;
  struct message_cookie_reply reply;
  uint8_t source[6] = {198u, 51u, 100u, 66u, 0x11u, 0x5cu};
  datagram_t forged;

  wireguard_create_cookie_reply(device_of(&s_server), &reply, message->mac1,
                                message->sender, source, sizeof(source));
  memset(&forged, 0, sizeof(forged));
  memcpy(forged.data, &reply, sizeof(reply));
  forged.length = sizeof(reply);
  s_now_ms += 10u;
  deliver(&s_client, &forged, &s_attacker_address, kAttackerPort);

  TEST_ASSERT_EQUAL(s_now_ms, peer_of(&s_client)->cookie_millis);
  assert_endpoint(&s_client, &s_server_address, kServerPort);
}

// Issue 3: the peer sets the plaintext length and need not pad it; an IPv4
// header is read only when all 20 bytes are there. IPv6 and other versions
// never reach the IP layer.
static void test_short_plaintexts_never_reach_the_ip_layer(void) {
  start_pair(false);
  (void)handshake_from(&s_client_address, kClientPort);
  uint8_t header[40] = {0x45u, 0u, 0u,  19u, 0u, 1u, 0u,  0u, 64u, 253u,
                        0u,    0u, 10u, 8u,  0u, 2u, 10u, 8u, 0u,  1u};
  const u32_t received_before = lwip_stats.ip.recv;

  s_now_ms += 10u;
  datagram_t short_packet = client_transport_with_plaintext(header, 19u);
  deliver(&s_server, &short_packet, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(s_now_ms, peer_of(&s_server)->last_rx);
  TEST_ASSERT_EQUAL(received_before, lwip_stats.ip.recv);

  datagram_t single_byte = client_transport_with_plaintext(header, 1u);
  deliver(&s_server, &single_byte, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(received_before, lwip_stats.ip.recv);

  header[3] = 40u;
  header[0] = 0x60u;
  datagram_t ipv6 = client_transport_with_plaintext(header, 40u);
  deliver(&s_server, &ipv6, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(received_before, lwip_stats.ip.recv);

  header[0] = 0x45u;
  header[3] = 20u;
  datagram_t full_header = client_transport_with_plaintext(header, 20u);
  deliver(&s_server, &full_header, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(received_before + 1u, lwip_stats.ip.recv);
}

// Issue 4: the greatest initiation timestamp is restored when the peer is
// added again, so a captured initiation cannot be replayed after a restart.
static void
test_a_restored_greatest_timestamp_rejects_a_replayed_initiation(void) {
  start_pair(false);
  const uint32_t sent_at = s_now_ms;
  const datagram_t initiation = client_initiation();
  uint8_t expected[WIREGUARD_TAI64N_LEN];
  uint8_t greatest[WIREGUARDIF_TIMESTAMP_LEN];
  size_t first = s_sent_count;

  deliver(&s_server, &initiation, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(1u, responses_since(first));
  tai64n_at(sent_at, expected);
  TEST_ASSERT_EQUAL(ERR_OK, wireguardif_peer_greatest_timestamp(
                                &s_server, 0u, greatest, sizeof(greatest)));
  TEST_ASSERT_EQUAL_MEMORY(expected, greatest, sizeof(expected));
  TEST_ASSERT_EQUAL(ERR_ARG,
                    wireguardif_peer_greatest_timestamp(
                        &s_server, 0u, greatest, sizeof(greatest) - 1u));

  // Restart with the saved value: the replay is ignored.
  stop_node(&s_server);
  start_node(&s_server, &s_server_init, kServerPrivateKey, kServerPort, 1u);
  add_peer(&s_server, s_client_public_key, NULL, 0u, 2u, 255u, greatest);
  s_now_ms += 60000u;
  first = s_sent_count;
  deliver(&s_server, &initiation, &s_attacker_address, kAttackerPort);
  TEST_ASSERT_EQUAL(0u, responses_since(first));
  TEST_ASSERT_FALSE(ip_addr_cmp(&peer_of(&s_server)->ip, &s_attacker_address));

  // Without it the same replay is accepted and answered to the attacker, who
  // still does not become the endpoint.
  stop_node(&s_server);
  start_node(&s_server, &s_server_init, kServerPrivateKey, kServerPort, 1u);
  add_peer(&s_server, s_client_public_key, NULL, 0u, 2u, 255u, NULL);
  first = s_sent_count;
  deliver(&s_server, &initiation, &s_attacker_address, kAttackerPort);
  (void)response_to(first, &s_attacker_address, kAttackerPort);
  TEST_ASSERT_FALSE(ip_addr_cmp(&peer_of(&s_server)->ip, &s_attacker_address));
}

// Issue 4, what the greatest timestamp cannot cover: an initiation of the
// client that never reached the server stays newer than every accepted one,
// so its replay passes, also long after the capture or after a device reset
// within the clock tolerance. The server answers it at its source but keeps
// the endpoint, and the tunnel traffic still goes to the client.
static void test_an_accepted_replayed_initiation_keeps_the_endpoint(void) {
  start_pair(false);
  (void)handshake_from(&s_client_address, kClientPort);

  s_now_ms += 1000u;
  const datagram_t captured = initiation_of(&s_client);

  s_now_ms += 10000u;
  const size_t first = s_sent_count;
  deliver(&s_server, &captured, &s_attacker_address, kAttackerPort);
  (void)response_to(first, &s_attacker_address, kAttackerPort);
  assert_endpoint(&s_server, &s_client_address, kClientPort);

  const datagram_t data = sends_inner_packet(&s_server, 1u, 2u);
  TEST_ASSERT_TRUE(ip_addr_cmp(&data.destination, &s_client_address));
  TEST_ASSERT_EQUAL(kClientPort, data.destination_port);
}

// The same gap seen from the active side: a replayed initiation of the server
// arrives while the client's own initiation waits for its response. The client
// answers it from the separate responder state, and the server's real
// response still completes the client's own handshake.
static void test_a_replayed_initiation_does_not_cancel_the_own_handshake(void) {
  start_pair(true);
  const datagram_t captured = initiation_of(&s_server);
  handshake_destroy(&peer_of(&s_server)->handshake); // long forgotten

  s_now_ms += 60000u;
  const datagram_t initiation = client_initiation();
  size_t first = s_sent_count;
  deliver(&s_server, &initiation, &s_client_address, kClientPort);
  const datagram_t response =
      response_to(first, &s_client_address, kClientPort);

  first = s_sent_count;
  deliver(&s_client, &captured, &s_attacker_address, kAttackerPort);
  (void)response_to(first, &s_attacker_address, kAttackerPort);
  assert_endpoint(&s_client, &s_server_address, kServerPort);

  deliver(&s_client, &response, &s_server_address, kServerPort);
  TEST_ASSERT_TRUE(peer_of(&s_client)->curr_keypair.valid);
  TEST_ASSERT_TRUE(peer_of(&s_client)->curr_keypair.initiator);
}

// Real initiations of both sides cross on the wire. Each side answers the
// other's initiation from its responder state and completes its own, so the
// tunnel carries traffic both ways without a retry.
static void test_crossing_initiations_both_complete(void) {
  start_pair(true);
  const datagram_t client_init = client_initiation();
  const datagram_t server_init = initiation_of(&s_server);

  size_t first = s_sent_count;
  deliver(&s_server, &client_init, &s_client_address, kClientPort);
  const datagram_t server_response =
      response_to(first, &s_client_address, kClientPort);
  first = s_sent_count;
  deliver(&s_client, &server_init, &s_server_address, kServerPort);
  const datagram_t client_response =
      response_to(first, &s_server_address, kServerPort);

  first = s_sent_count;
  deliver(&s_client, &server_response, &s_server_address, kServerPort);
  const datagram_t client_keepalive = *sent_once_since(first);
  first = s_sent_count;
  deliver(&s_server, &client_response, &s_client_address, kClientPort);
  const datagram_t server_keepalive = *sent_once_since(first);
  deliver(&s_server, &client_keepalive, &s_client_address, kClientPort);
  deliver(&s_client, &server_keepalive, &s_server_address, kServerPort);
  TEST_ASSERT_TRUE(peer_of(&s_client)->curr_keypair.initiator);
  TEST_ASSERT_TRUE(peer_of(&s_server)->curr_keypair.initiator);

  const u32_t received_before = lwip_stats.ip.recv;
  const datagram_t to_server = client_sends_inner_packet();
  deliver(&s_server, &to_server, &s_client_address, kClientPort);
  const datagram_t to_client = sends_inner_packet(&s_server, 1u, 2u);
  deliver(&s_client, &to_client, &s_server_address, kServerPort);
  TEST_ASSERT_EQUAL(received_before + 2u, lwip_stats.ip.recv);
}

// Issue 5: the per-peer limit (MAX_INITIATIONS_PER_SECOND) wrapped around
// and only held within the same millisecond.
static void test_initiations_faster_than_the_rate_limit_are_ignored(void) {
  start_pair(false);
  const datagram_t initiation = client_initiation();
  datagram_t next;
  size_t first = s_sent_count;

  deliver(&s_server, &initiation, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(1u, responses_since(first));

  s_now_ms += (1000u / MAX_INITIATIONS_PER_SECOND) - 1u;
  next = initiation_of(&s_client);
  first = s_sent_count;
  deliver(&s_server, &next, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(0u, responses_since(first));

  s_now_ms += 1u;
  next = initiation_of(&s_client);
  first = s_sent_count;
  deliver(&s_server, &next, &s_client_address, kClientPort);
  TEST_ASSERT_EQUAL(1u, responses_since(first));
}

// Issue 6: after 3 x Reject-After-Time without a new session every key and
// the handshake state are wiped and the configured endpoint comes back. The
// reset used to need a current keypair, which is gone after 180 s. The
// session starts at millisecond 0, where the counter also stands after it
// wraps, and must not count as 49 days old.
static void
test_peer_resets_after_three_reject_after_times_without_a_session(void) {
  s_now_ms = 0u;
  start_pair(true);
  const uint32_t session_at = s_now_ms;
  (void)handshake_from(&s_rebound_address, kClientPort + 1u);
  assert_endpoint(&s_server, &s_rebound_address, kClientPort + 1u);

  service(&s_server);
  TEST_ASSERT_TRUE(peer_of(&s_server)->curr_keypair.valid);

  s_now_ms = session_at + (REJECT_AFTER_TIME * 3u - 1u) * 1000u;
  service(&s_server);
  assert_endpoint(&s_server, &s_rebound_address, kClientPort + 1u);
  TEST_ASSERT_FALSE(peer_of(&s_server)->curr_keypair.valid);

  s_now_ms = session_at + REJECT_AFTER_TIME * 3u * 1000u;
  service(&s_server);
  assert_endpoint(&s_server, &s_client_address, kClientPort);
  struct wireguard_peer *peer = peer_of(&s_server);
  TEST_ASSERT_FALSE(peer->has_session);
  TEST_ASSERT_TRUE(all_zero(&peer->curr_keypair, sizeof(peer->curr_keypair)));
  TEST_ASSERT_TRUE(all_zero(&peer->prev_keypair, sizeof(peer->prev_keypair)));
  TEST_ASSERT_TRUE(all_zero(&peer->next_keypair, sizeof(peer->next_keypair)));
  TEST_ASSERT_FALSE(peer->handshake.valid);
  TEST_ASSERT_TRUE(all_zero(peer->handshake.ephemeral_private,
                            sizeof(peer->handshake.ephemeral_private)));
  TEST_ASSERT_TRUE(all_zero(peer->handshake.chaining_key,
                            sizeof(peer->handshake.chaining_key)));
}

// Without a configured endpoint the reset keeps the learned one.
static void
test_peer_reset_keeps_a_learned_endpoint_without_a_configured_one(void) {
  start_pair(false);
  const uint32_t session_at = s_now_ms;
  (void)handshake_from(&s_rebound_address, kClientPort + 1u);

  s_now_ms = session_at + REJECT_AFTER_TIME * 3u * 1000u;
  service(&s_server);
  TEST_ASSERT_FALSE(peer_of(&s_server)->has_session);
  assert_endpoint(&s_server, &s_rebound_address, kClientPort + 1u);
}

// Issue 6: expired previous keypairs were never destroyed, so the peer
// stayed "up" with no usable session.
static void test_expired_previous_keypairs_are_destroyed(void) {
  start_pair(false);
  const uint32_t first_session_at = s_now_ms;
  (void)handshake_from(&s_client_address, kClientPort);

  // Sending after Rekey-After-Time asks for a new handshake; the first
  // session becomes the previous one.
  s_now_ms = first_session_at + (REKEY_AFTER_TIME + 1u) * 1000u;
  (void)client_sends_inner_packet();
  const uint32_t second_session_at = s_now_ms;
  (void)handshake_from(&s_client_address, kClientPort);
  TEST_ASSERT_TRUE(peer_of(&s_client)->prev_keypair.valid);

  s_now_ms = first_session_at + REJECT_AFTER_TIME * 1000u;
  service(&s_client);
  TEST_ASSERT_FALSE(peer_of(&s_client)->prev_keypair.valid);
  TEST_ASSERT_TRUE(peer_of(&s_client)->curr_keypair.valid);

  s_now_ms = second_session_at + REJECT_AFTER_TIME * 1000u;
  service(&s_client);
  TEST_ASSERT_EQUAL(ERR_CONN,
                    wireguardif_peer_is_up(&s_client, 0u, NULL, NULL));
}

// A 4-character block has at most two '=' and decodes to at least one byte.
static void test_base64_rejects_a_block_with_three_padding_characters(void) {
  uint8_t out[4];
  size_t length = sizeof(out);
  TEST_ASSERT_FALSE(wireguard_base64_decode("A===", out, &length));

  length = sizeof(out);
  TEST_ASSERT_TRUE(wireguard_base64_decode("AQ==", out, &length));
  TEST_ASSERT_EQUAL(1u, length);
  TEST_ASSERT_EQUAL(0x01u, out[0]);

  length = sizeof(out);
  TEST_ASSERT_TRUE(wireguard_base64_decode("AQI=", out, &length));
  TEST_ASSERT_EQUAL(2u, length);
  TEST_ASSERT_EQUAL(0x02u, out[1]);
}

int main(void) {
  lwip_init();
  RUN_TEST(test_replayed_transport_packets_do_not_move_the_endpoint);
  RUN_TEST(test_a_valid_cookie_reply_does_not_move_the_endpoint);
  RUN_TEST(test_short_plaintexts_never_reach_the_ip_layer);
  RUN_TEST(test_a_restored_greatest_timestamp_rejects_a_replayed_initiation);
  RUN_TEST(test_an_accepted_replayed_initiation_keeps_the_endpoint);
  RUN_TEST(test_a_replayed_initiation_does_not_cancel_the_own_handshake);
  RUN_TEST(test_crossing_initiations_both_complete);
  RUN_TEST(test_initiations_faster_than_the_rate_limit_are_ignored);
  RUN_TEST(test_peer_resets_after_three_reject_after_times_without_a_session);
  RUN_TEST(test_peer_reset_keeps_a_learned_endpoint_without_a_configured_one);
  RUN_TEST(test_expired_previous_keypairs_are_destroyed);
  RUN_TEST(test_base64_rejects_a_block_with_three_padding_characters);
  printf("protocol tests: %d run, %d failed\n", s_tests_run, s_tests_failed);
  return (s_tests_failed == 0) ? 0 : 1;
}
