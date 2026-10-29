/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names
 * of its contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef WIREGUARD_ALLOWED_IP_H
#define WIREGUARD_ALLOWED_IP_H

#include "lwip/ip.h"
#include "wireguard.h"

/*
 * Cryptokey routing on receive (WireGuard whitepaper, section 3): a decrypted
 * inner packet is accepted only when its source address is inside one of the
 * peer's AllowedIPs.
 */
static inline bool
wireguard_ipv4_source_is_allowed(const struct wireguard_peer *peer,
                                 const struct ip_hdr *iphdr) {
  ip_addr_t source;
  int index;

  if ((peer == NULL) || (iphdr == NULL)) {
    return false;
  }

  ip_addr_copy_from_ip4(source, iphdr->src);
  for (index = 0; index < WIREGUARD_MAX_SRC_IPS; ++index) {
    const struct wireguard_allowed_ip *allowed =
        &peer->allowed_source_ips[index];
    if (allowed->valid &&
        ip_addr_netcmp(&source, &allowed->ip, ip_2_ip4(&allowed->mask))) {
      return true;
    }
  }

  return false;
}

#endif /* WIREGUARD_ALLOWED_IP_H */
