/*
 * lwIP options for the host tests: the pbuf and heap code for the helper
 * tests, and the IPv4, UDP and timer code that the two WireGuard engines of
 * the protocol test run on. Statistics are on, so a test can read
 * lwip_stats.mem and lwip_stats.ip.
 */
#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_TIMERS 1

#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_ARP 0
#define LWIP_ICMP 0
#define LWIP_RAW 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_UDP 1
#define LWIP_TCP 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_CHECKSUM_ON_COPY 0
#define IP_REASSEMBLY 0
#define IP_FRAG 0

#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0
#define MEM_ALIGNMENT 8
#define MEM_SIZE (64 * 1024)
#define PBUF_POOL_SIZE 16
#define PBUF_POOL_BUFSIZE 256
/* One periodic timer per WireGuard engine: two in the protocol test. */
#define MEMP_NUM_SYS_TIMEOUT (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 2)

#define LWIP_STATS 1
#define LWIP_STATS_DISPLAY 0
#define MEM_STATS 1
#define MEMP_STATS 0
#define SYS_STATS 0
#define LINK_STATS 0
#define IP_STATS 1
#define UDP_STATS 0

#endif
