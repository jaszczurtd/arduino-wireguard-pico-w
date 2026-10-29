// Host tests for the helper headers and the crypto primitives of the library:
//   wireguard_replay.h      anti-replay ring window
//   wireguard_pbuf.h        contiguous pbuf for the message parsers
//   wireguard_allowed_ip.h  AllowedIPs check on the inner source address
//   crypto.c, crypto/refc/  BLAKE2s, X25519 and ChaCha20-Poly1305 vectors
// Built by run.sh against real lwIP sources (pbuf, heap), no board needed.

#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/stats.h"

extern "C" {
#include "crypto.h"
}
#include "wireguard_allowed_ip.h"
#include "wireguard_pbuf.h"
#include "wireguard_replay.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                            \
  do {                                                                         \
    ++g_checks;                                                                \
    if (!(cond)) {                                                             \
      std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,    \
                   #cond);                                                     \
      ++g_failures;                                                            \
    }                                                                          \
  } while (0)

// ---- replay window ---------------------------------------------------------

static void test_replay_accepts_zero_once_and_tracks_reordering() {
  wireguard_replay_state_t replay = {};

  CHECK(wireguard_replay_check(&replay, 0u));
  CHECK(!wireguard_replay_check(&replay, 0u));
  CHECK(wireguard_replay_check(&replay, 9000u));
  CHECK(wireguard_replay_check(&replay, 1000u));
  CHECK(!wireguard_replay_check(&replay, 1000u));
  CHECK(!wireguard_replay_check(&replay, 839u));
  CHECK(wireguard_replay_check(&replay, 840u));
}

static void test_replay_handles_word_wrap_and_protocol_limit() {
  wireguard_replay_state_t replay = {};

  for (uint64_t sequence = 1u; sequence <= 8300u; ++sequence) {
    if (sequence != 140u) {
      CHECK(wireguard_replay_check(&replay, sequence));
    }
  }
  CHECK(!wireguard_replay_check(&replay, 1u));
  CHECK(wireguard_replay_check(&replay, 140u));
  CHECK(!wireguard_replay_check(&replay, 140u));
  CHECK(!wireguard_replay_check(&replay,
                                WIREGUARD_REPLAY_REJECT_AFTER_MESSAGES));
}

static void test_replay_reset_forgets_history_and_rejects_null() {
  wireguard_replay_state_t replay = {};

  CHECK(wireguard_replay_check(&replay, 5u));
  CHECK(!wireguard_replay_check(&replay, 5u));
  wireguard_replay_reset(&replay);
  CHECK(wireguard_replay_check(&replay, 5u));
  CHECK(!wireguard_replay_check(nullptr, 1u));
  wireguard_replay_reset(nullptr); // must not crash
}

// ---- contiguous pbuf -------------------------------------------------------

static void test_pbuf_coalesces_chain_without_truncation() {
  const mem_size_t used_before = lwip_stats.mem.used;

  pbuf *first = pbuf_alloc(PBUF_RAW, 3u, PBUF_RAM);
  pbuf *second = pbuf_alloc(PBUF_RAW, 5u, PBUF_RAM);
  CHECK(first != nullptr && second != nullptr);
  CHECK(pbuf_take(first, "abc", 3u) == ERR_OK);
  CHECK(pbuf_take(second, "defgh", 5u) == ERR_OK);
  pbuf_cat(first, second);
  CHECK(first->next != nullptr);
  CHECK(first->len == 3u && first->tot_len == 8u);

  pbuf *contiguous = wireguard_pbuf_make_contiguous(first);
  CHECK(contiguous != nullptr);
  if (contiguous != nullptr) {
    CHECK(contiguous->next == nullptr);
    CHECK(contiguous->len == 8u);
    CHECK(contiguous->tot_len == 8u);
    CHECK(std::memcmp(contiguous->payload, "abcdefgh", 8u) == 0);
    pbuf_free(contiguous);
  }
  CHECK(lwip_stats.mem.used == used_before);
}

static void test_pbuf_keeps_already_contiguous_packet() {
  const mem_size_t used_before = lwip_stats.mem.used;

  pbuf *packet = pbuf_alloc(PBUF_RAW, 4u, PBUF_RAM);
  CHECK(packet != nullptr);
  CHECK(pbuf_take(packet, "data", 4u) == ERR_OK);

  CHECK(wireguard_pbuf_make_contiguous(packet) == packet);
  CHECK(std::memcmp(packet->payload, "data", 4u) == 0);
  pbuf_free(packet);
  CHECK(lwip_stats.mem.used == used_before);
}

static void test_pbuf_rejects_null_and_frees_when_coalescing_fails() {
  CHECK(wireguard_pbuf_make_contiguous(nullptr) == nullptr);

  // A chain larger than the whole heap cannot be cloned: the helper must
  // free the original chain and report failure without leaking.
  const mem_size_t used_before = lwip_stats.mem.used;
  const u16_t segment = 16000u;
  pbuf *head = nullptr;
  int segments = 0;
  for (int i = 0; i < 3; ++i) {
    pbuf *p = pbuf_alloc(PBUF_RAW, segment, PBUF_RAM);
    if (p == nullptr) {
      break;
    }
    ++segments;
    if (head == nullptr) {
      head = p;
    } else {
      pbuf_cat(head, p);
    }
  }
  CHECK(segments >= 2);
  if (head != nullptr && segments >= 2) {
    // The remaining heap is smaller than tot_len, so pbuf_clone() fails.
    CHECK(wireguard_pbuf_make_contiguous(head) == nullptr);
  } else if (head != nullptr) {
    pbuf_free(head);
  }
  CHECK(lwip_stats.mem.used == used_before);
}

// ---- AllowedIPs on the inner source ---------------------------------------

static void set_ipv4(ip_addr_t *out, uint8_t a, uint8_t b, uint8_t c,
                     uint8_t d) {
  IP_ADDR4(out, a, b, c, d);
}

static void set_hdr(ip_hdr *hdr, uint32_t src, uint32_t dest) {
  std::memset(hdr, 0, sizeof(*hdr));
  IPH_VHL_SET(hdr, 4, 5);
  hdr->src.addr = PP_HTONL(src);
  hdr->dest.addr = PP_HTONL(dest);
}

static void test_allowed_ip_checks_inner_source_not_destination() {
  wireguard_peer peer;
  std::memset(&peer, 0, sizeof(peer));
  set_ipv4(&peer.allowed_source_ips[0].ip, 10, 77, 0, 0);
  set_ipv4(&peer.allowed_source_ips[0].mask, 255, 255, 255, 0);
  peer.allowed_source_ips[0].valid = true;

  ip_hdr hdr;
  set_hdr(&hdr, 0x0A4D0001u, 0x0A4D0002u); // 10.77.0.1 -> 10.77.0.2
  CHECK(wireguard_ipv4_source_is_allowed(&peer, &hdr));

  // Destination inside AllowedIPs but source outside: rejected.
  set_hdr(&hdr, 0xC0A80201u, 0x0A4D0002u); // 192.168.2.1 -> 10.77.0.2
  CHECK(!wireguard_ipv4_source_is_allowed(&peer, &hdr));

  // Source inside, destination elsewhere: accepted (routing is on source).
  set_hdr(&hdr, 0x0A4D00FEu, 0xC0A80201u); // 10.77.0.254 -> 192.168.2.1
  CHECK(wireguard_ipv4_source_is_allowed(&peer, &hdr));

  // A second, later entry is also consulted.
  set_ipv4(&peer.allowed_source_ips[1].ip, 192, 168, 2, 0);
  set_ipv4(&peer.allowed_source_ips[1].mask, 255, 255, 255, 0);
  peer.allowed_source_ips[1].valid = true;
  set_hdr(&hdr, 0xC0A80201u, 0x0A4D0002u);
  CHECK(wireguard_ipv4_source_is_allowed(&peer, &hdr));

  // Invalid entries do not match.
  peer.allowed_source_ips[0].valid = false;
  peer.allowed_source_ips[1].valid = false;
  CHECK(!wireguard_ipv4_source_is_allowed(&peer, &hdr));
}

static void test_allowed_ip_default_route_and_null_arguments() {
  wireguard_peer peer;
  std::memset(&peer, 0, sizeof(peer));
  set_ipv4(&peer.allowed_source_ips[0].ip, 0, 0, 0, 0);
  set_ipv4(&peer.allowed_source_ips[0].mask, 0, 0, 0, 0);
  peer.allowed_source_ips[0].valid = true;

  ip_hdr hdr;
  set_hdr(&hdr, 0x08080808u, 0x0A4D0002u); // 8.8.8.8 -> 10.77.0.2
  CHECK(wireguard_ipv4_source_is_allowed(&peer, &hdr));

  CHECK(!wireguard_ipv4_source_is_allowed(nullptr, &hdr));
  CHECK(!wireguard_ipv4_source_is_allowed(&peer, nullptr));
}

// ---- crypto primitives ----------------------------------------------------

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
  if (std::strlen(hex) != out_len * 2u) {
    return false;
  }
  for (size_t i = 0; i < out_len; ++i) {
    unsigned value = 0;
    if (std::sscanf(hex + 2u * i, "%2x", &value) != 1) {
      return false;
    }
    out[i] = (uint8_t)value;
  }
  return true;
}

static void test_crypto_zero_and_equal() {
  uint8_t secret[16];
  for (size_t i = 0; i < sizeof(secret); ++i) secret[i] = (uint8_t)(0xA0u + i);
  crypto_zero(secret, sizeof(secret));
  bool all_zero = true;
  for (size_t i = 0; i < sizeof(secret); ++i) all_zero = all_zero && secret[i] == 0u;
  CHECK(all_zero);

  uint8_t a[8] = {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u};
  uint8_t b[8];
  std::memcpy(b, a, sizeof(a));
  CHECK(crypto_equal(a, b, sizeof(a)));
  b[3] ^= 0x55u;
  CHECK(!crypto_equal(a, b, sizeof(a)));
  CHECK(crypto_equal(a, b, 0u));
}

static void test_blake2s_known_vector_for_abc() {
  static const char msg[] = "abc";
  uint8_t digest[32];
  uint8_t expected[32];
  CHECK(hex_to_bytes("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
                     expected, sizeof(expected)));
  CHECK(blake2s(digest, sizeof(digest), NULL, 0u, msg, sizeof(msg) - 1u) == 0);
  CHECK(std::memcmp(expected, digest, sizeof(digest)) == 0);
}

static void test_x25519_rfc7748_vectors() {
  uint8_t alice_private[32], alice_public_expected[32];
  uint8_t bob_private[32], bob_public_expected[32];
  uint8_t shared_expected[32];
  uint8_t alice_public[32], bob_public[32], shared_ab[32], shared_ba[32];

  CHECK(hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                     alice_private, sizeof(alice_private)));
  CHECK(hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                     alice_public_expected, sizeof(alice_public_expected)));
  CHECK(hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                     bob_private, sizeof(bob_private)));
  CHECK(hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                     bob_public_expected, sizeof(bob_public_expected)));
  CHECK(hex_to_bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                     shared_expected, sizeof(shared_expected)));

  CHECK(x25519(alice_public, alice_private, X25519_BASE_POINT, 1) == 0);
  CHECK(x25519(bob_public, bob_private, X25519_BASE_POINT, 1) == 0);
  CHECK(std::memcmp(alice_public_expected, alice_public, sizeof(alice_public)) == 0);
  CHECK(std::memcmp(bob_public_expected, bob_public, sizeof(bob_public)) == 0);

  CHECK(x25519(shared_ab, alice_private, bob_public, 1) == 0);
  CHECK(x25519(shared_ba, bob_private, alice_public, 1) == 0);
  CHECK(std::memcmp(shared_expected, shared_ab, sizeof(shared_ab)) == 0);
  CHECK(std::memcmp(shared_expected, shared_ba, sizeof(shared_ba)) == 0);
}

static void test_chacha20poly1305_roundtrip_and_tag_validation() {
  uint8_t key[32], aad[11], plain[48];
  uint8_t cipher[sizeof(plain) + 16u];
  uint8_t decrypted[sizeof(plain)];
  uint8_t tampered[sizeof(cipher)];
  uint8_t unchanged[sizeof(decrypted)];

  for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(0x11u + i);
  for (size_t i = 0; i < sizeof(aad); ++i) aad[i] = (uint8_t)(0x70u + i);
  for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i ^ 0x5Au);

  chacha20poly1305_encrypt(cipher, plain, sizeof(plain), aad, sizeof(aad),
                           0x0123456789ABCDEFULL, key);
  CHECK(chacha20poly1305_decrypt(decrypted, cipher, sizeof(cipher), aad, sizeof(aad),
                                 0x0123456789ABCDEFULL, key));
  CHECK(std::memcmp(plain, decrypted, sizeof(plain)) == 0);

  std::memcpy(tampered, cipher, sizeof(cipher));
  tampered[sizeof(tampered) - 1u] ^= 0x01u;
  std::memset(decrypted, 0xCC, sizeof(decrypted));
  std::memcpy(unchanged, decrypted, sizeof(decrypted));
  CHECK(!chacha20poly1305_decrypt(decrypted, tampered, sizeof(tampered), aad, sizeof(aad),
                                  0x0123456789ABCDEFULL, key));
  CHECK(std::memcmp(unchanged, decrypted, sizeof(decrypted)) == 0);

  // A different nonce or key must not authenticate either.
  CHECK(!chacha20poly1305_decrypt(decrypted, cipher, sizeof(cipher), aad, sizeof(aad),
                                  0x0123456789ABCDEEULL, key));
  key[0] ^= 0x80u;
  CHECK(!chacha20poly1305_decrypt(decrypted, cipher, sizeof(cipher), aad, sizeof(aad),
                                  0x0123456789ABCDEFULL, key));
}

int main() {
  mem_init();
  memp_init();

  test_crypto_zero_and_equal();
  test_blake2s_known_vector_for_abc();
  test_x25519_rfc7748_vectors();
  test_chacha20poly1305_roundtrip_and_tag_validation();
  test_replay_accepts_zero_once_and_tracks_reordering();
  test_replay_handles_word_wrap_and_protocol_limit();
  test_replay_reset_forgets_history_and_rejects_null();
  test_pbuf_coalesces_chain_without_truncation();
  test_pbuf_keeps_already_contiguous_packet();
  test_pbuf_rejects_null_and_frees_when_coalescing_fails();
  test_allowed_ip_checks_inner_source_not_destination();
  test_allowed_ip_default_route_and_null_arguments();

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
