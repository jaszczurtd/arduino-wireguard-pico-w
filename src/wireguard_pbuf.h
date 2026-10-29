#ifndef WIREGUARD_PBUF_H
#define WIREGUARD_PBUF_H

#include "lwip/pbuf.h"

/*
 * Return one contiguous pbuf owned by the caller. pbuf_coalesce() either
 * returns the original packet or frees it after creating the replacement.
 * Allocation failure leaves the original chain intact, which is rejected and
 * freed here because WireGuard message parsers require contiguous storage.
 */
static inline struct pbuf *wireguard_pbuf_make_contiguous(struct pbuf *packet) {
  if (packet == NULL) {
    return NULL;
  }
  packet = pbuf_coalesce(packet, PBUF_RAW);
  if (packet->next != NULL || packet->payload == NULL ||
      packet->len != packet->tot_len) {
    pbuf_free(packet);
    return NULL;
  }
  return packet;
}

#endif
