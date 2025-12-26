#include "wg_port_pico.h"

// Format using va_list
static void vdeb(const char *fmt, va_list ap) {
  // NOTE: This is not thread-safe / not multi-core safe.
  vsnprintf(deb_buffer, sizeof(deb_buffer), fmt, ap);
  Serial.print(deb_buffer);
}

// Convenience wrapper (printf-like)
void dbg(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  vdeb(format, ap);
  va_end(ap);
}

// Log function used by macros
void wg_logf_(const char *lvl, const char *fmt, ...) {
  Serial.print("[");
  Serial.print(lvl);
  Serial.print("] ");

  va_list ap;
  va_start(ap, fmt);
  vdeb(fmt, ap);
  va_end(ap);

  Serial.println();
}