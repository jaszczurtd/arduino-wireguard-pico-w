# Hardware test

`wg_services/wg_services.ino` runs the library against a Linux WireGuard
endpoint and prints one `CHECK <name> pass=<0|1>` line per check, `SOAK` lines
during the soak and a final `SUMMARY pass=<n> fail=<n>`. The checks follow the
network services suite of JaszczurHAL: split tunnel three times (handshake,
UDP echo, TCP echo, MQTT CONNECT/CONNACK, the LAN outside the tunnel, `end()`
with a TCP connection still open), full tunnel, the endpoint given as a host
name, WiFi lost under an active tunnel, and a soak through the split tunnel
with UDP echo and one TCP connection kept open across the key renewals.

## Host side

One Linux machine inside the WiFi LAN:

1. A WireGuard interface with address `10.77.0.1/24`, listening on UDP 51821,
   with the board as its peer (`AllowedIPs = 10.77.0.2/32`). Creating it needs
   root, for example with `wg-quick` or a NetworkManager profile; the rest runs
   as an ordinary user.
2. UDP echo on `10.77.0.1:42045`, TCP echo on `0.0.0.0:42049` (it is reached
   through the tunnel and on the LAN) and an MQTT broker on `10.77.0.1:18883`.
   Any echo server and any MQTT 3.1.1 broker will do; the test only needs the
   payload back and a `CONNACK` with return code 0.

## Board side

Copy `wg_services/secrets.h.example` to `wg_services/secrets.h`, fill in the
WiFi credentials, the keys, the host address and port, build for
`rp2040:rp2040:rpipicow` (or `rpipico2w`) and watch the serial port at 115200.
`-DSOAK_SECONDS=600` lengthens the soak (default 300 s, the keys renew every
120 s), `-DWG_LOG_LEVEL=5` adds the library's packet trace.
