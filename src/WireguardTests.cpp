#include "WireguardTests.h"

void test_wireguard_random() {
  Serial.println("=== Testing random generator ===");
  uint8_t rand_test[4];
  wireguard_random_bytes(rand_test, 4);
  Serial.printf("Random bytes: %02X%02X%02X%02X\n", 
                rand_test[0], rand_test[1], rand_test[2], rand_test[3]);
}

void test_crypto_primitives() {
    Serial.println("=== Testing crypto primitives ===");
    
    // Test BLAKE2s
    uint8_t hash[32];
    uint8_t test_data[] = "WireGuard test";
    
    if (blake2s(hash, 32, NULL, 0, test_data, sizeof(test_data)-1) == 0) {
        Serial.print("BLAKE2s OK: ");
        for(int i=0; i<4; i++) Serial.printf("%02x", hash[i]);
        Serial.println("...");
    } else {
        Serial.println("BLAKE2s FAILED!");
    }
    
    // Test X25519 (basic)
    uint8_t private_key[32] = {0};
    uint8_t public_key[32];
    uint8_t basepoint[32] = {9};
    
    // fill private key with testing data
    for(int i=0; i<32; i++) private_key[i] = i;
    
    int result = x25519(public_key, private_key, basepoint, 1);
    Serial.printf("X25519 result: %d\n", result);
    if(result == 0) {
        Serial.print("X25519 OK, public key: ");
        for(int i=0; i<4; i++) Serial.printf("%02x", public_key[i]);
        Serial.println("...");
    } else {
        Serial.println("X25519 FAILED!");
    }
    
    // Test ChaCha20
    struct chacha20_ctx ctx;
    uint8_t key[32] = {0};
    uint8_t plaintext[64] = {0};
    uint8_t ciphertext[64];
    
    chacha20_init(&ctx, key, 0);
    chacha20(&ctx, ciphertext, plaintext, 64);
    Serial.println("ChaCha20 basic init OK");
}

void test_udp_send() {
    Serial.println("=== Testing UDP send ===");
    
    struct udp_pcb *test_pcb = udp_new();
    if (!test_pcb) {
        Serial.println("Failed to create UDP PCB");
        return;
    }
    
    err_t err = udp_bind(test_pcb, IP_ADDR_ANY, 12345);
    if (err != ERR_OK) {
        Serial.printf("UDP bind failed: %d\n", err);
        udp_remove(test_pcb);
        return;
    }
    
    // prepare testing pakiet
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 10, PBUF_RAM);
    if (!p) {
        Serial.println("Failed to allocate pbuf");
        udp_remove(test_pcb);
        return;
    }
    
    // fill with data
    memset(p->payload, 0x41, 10);  // "AAAAAAAAAA"
    
    // destination (Google DNS for test)
    ip_addr_t dest;
    IP4_ADDR(&dest, 8, 8, 8, 8);
    
    Serial.println("Sending test UDP packet to 8.8.8.8:53");
    err = udp_sendto(test_pcb, p, &dest, 53);
    Serial.printf("udp_sendto returned: %d\n", err);
    
    pbuf_free(p);
    udp_remove(test_pcb);
    Serial.println("UDP test completed");
}

// Parses IPv4 in dotted-decimal form: "A.B.C.D"
// Returns true on success, false on format/range error.
static bool parseIPv4(const char *s, uint8_t out[4]) {
  if (!s) return false;

  uint32_t val = 0;
  int part = 0;
  int digits = 0;

  // Reject leading/trailing spaces (optional: you can allow them if you want)
  if (*s == ' ' || *s == '\t') return false;

  while (*s) {
    char c = *s++;

    if (c >= '0' && c <= '9') {
      val = val * 10u + (uint32_t)(c - '0');
      digits++;
      if (digits > 3) return false;      // too many digits in a part
      if (val > 255u) return false;      // out of range
    } else if (c == '.') {
      if (digits == 0) return false;     // empty part like "1..2"
      if (part >= 3) return false;       // too many dots/parts
      out[part++] = (uint8_t)val;
      val = 0;
      digits = 0;
    } else {
      return false;                      // invalid character
    }
  }

  // finalize last part
  if (digits == 0) return false;
  if (part != 3) return false;           // must have exactly 3 dots
  out[3] = (uint8_t)val;

  return true;
}

void test_wireguard_handshake_manual(const char *ipStr, int port) {
    Serial.println("=== Manual WireGuard Handshake Test ===");
    
    // sent packet to WireGuard by hand
    struct udp_pcb *pcb = udp_new();
    udp_bind(pcb, IP_ADDR_ANY, port);
    
    // prepare server adress
    ip_addr_t server_addr;
    uint8_t o[4];
    if (!parseIPv4(ipStr, o)) {
        Serial.println("invalid address");
        return;
    }
    IP4_ADDR(&server_addr, o[0], o[1], o[2], o[3]);
    
    // WireGuard packet (148 bytes)
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 148, PBUF_RAM);
    memset(p->payload, 0, 148);
    
    // type=0x01 (handshake initiation)
    ((uint8_t*)p->payload)[0] = 0x01;
    
    Serial.println("Sending manual WG packet...");
    err_t err = udp_sendto(pcb, p, &server_addr, port);
    Serial.printf("Manual send result: %d\n", err);
    
    pbuf_free(p);
    udp_remove(pcb);
}
