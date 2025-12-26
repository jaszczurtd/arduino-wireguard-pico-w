
#include <Arduino.h>
#include <WiFi.h>

#ifdef __cplusplus
extern "C" {
#endif

// Declare the functions we need
#include "crypto/refc/chacha20.h"
#include "crypto/refc/x25519.h"
#include "crypto/refc/blake2s.h"
#include "wireguard-platform.h"

#ifdef __cplusplus
}
#endif

void test_wireguard_random();
void test_crypto_primitives();
void test_udp_send();
void test_wireguard_handshake_manual(const char *ipStr, int port);
