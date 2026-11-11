/*
 * Stand-in for the Arduino core header on the host. The engine sources
 * (wireguard.c, wireguardif.c) include it through wg_port_pico.h but use none
 * of its declarations outside DEBUG_DEEP builds.
 */
#ifndef WG_HOST_FAKE_ARDUINO_H
#define WG_HOST_FAKE_ARDUINO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#endif
