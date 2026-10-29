#include "wg_port_pico.h"

#include <pico/platform.h>

#include <stdint.h>

namespace {

struct LogSlot {
    uint16_t len;
    char text[WG_LOG_LINE_MAX];
};

// Single producer (the lwIP background IRQ) advances s_head, single consumer
// (wg_log_flush() in thread context) advances s_tail. Both are plain 32-bit
// stores with release/acquire ordering, so no read-modify-write atomics are
// needed and the ring works across cores too.
LogSlot s_slots[WG_LOG_ISR_SLOTS];
volatile uint32_t s_head = 0u;
volatile uint32_t s_tail = 0u;

// Lines dropped because the queue was full. Written by the producer only;
// the consumer remembers how many it has already reported.
volatile uint32_t s_dropped = 0u;
uint32_t s_dropped_reported = 0u;

// Formats "[lvl] " + message + "\n" into dst. lvl == 0 means raw text:
// no prefix and no newline (dbg()). Returns the number of bytes stored,
// always smaller than size; dst is NUL-terminated.
size_t format_line(char *dst, size_t size, char lvl, const char *fmt, va_list ap) {
    size_t pos = 0u;
    if (lvl != 0) {
        dst[0] = '[';
        dst[1] = lvl;
        dst[2] = ']';
        dst[3] = ' ';
        pos = 4u;
    }

    int n = vsnprintf(dst + pos, size - pos, fmt, ap);
    if (n < 0) {
        n = 0;
    }
    pos += (size_t)n;

    if (lvl != 0) {
        if (pos > size - 2u) {
            pos = size - 2u;  // truncated: keep room for '\n' and NUL
        }
        dst[pos++] = '\n';
    } else if (pos > size - 1u) {
        pos = size - 1u;
    }
    dst[pos] = '\0';
    return pos;
}

void queue_from_isr(char lvl, const char *fmt, va_list ap) {
    const uint32_t head = s_head;  // producer-owned
    const uint32_t tail = __atomic_load_n(&s_tail, __ATOMIC_ACQUIRE);
    if (head - tail >= (uint32_t)WG_LOG_ISR_SLOTS) {
        s_dropped = s_dropped + 1u;
        return;
    }

    LogSlot &slot = s_slots[head % WG_LOG_ISR_SLOTS];
    slot.len = (uint16_t)format_line(slot.text, sizeof(slot.text), lvl, fmt, ap);
    __atomic_store_n(&s_head, head + 1u, __ATOMIC_RELEASE);
}

void emit_direct(char lvl, const char *fmt, va_list ap) {
    // Not reachable from an IRQ by construction. The guard stays so that a
    // future caller cannot drag Serial into the background context: the line
    // is counted as dropped instead.
    if (wg_log_in_isr()) {
        s_dropped = s_dropped + 1u;
        return;
    }

    // Queued lines are older than this one; print them first.
    wg_log_flush();

    char line[WG_LOG_LINE_MAX];
    const size_t len = format_line(line, sizeof(line), lvl, fmt, ap);
    Serial.write((const uint8_t *)line, len);
}

void log_line(char lvl, const char *fmt, va_list ap) {
    if (wg_log_in_isr()) {
        queue_from_isr(lvl, fmt, ap);
    } else {
        emit_direct(lvl, fmt, ap);
    }
}

} // namespace

extern "C" bool wg_log_in_isr(void) {
    return __get_current_exception() != 0u;
}

extern "C" void wg_log_flush(void) {
    if (wg_log_in_isr()) {
        return;
    }

    for (;;) {
        const uint32_t tail = s_tail;  // consumer-owned
        const uint32_t head = __atomic_load_n(&s_head, __ATOMIC_ACQUIRE);
        if (tail == head) {
            break;
        }
        const LogSlot &slot = s_slots[tail % WG_LOG_ISR_SLOTS];
        Serial.write((const uint8_t *)slot.text, slot.len);
        __atomic_store_n(&s_tail, tail + 1u, __ATOMIC_RELEASE);
    }

    const uint32_t dropped = s_dropped;
    if (dropped != s_dropped_reported) {
        const unsigned long count = (unsigned long)(dropped - s_dropped_reported);
        s_dropped_reported = dropped;
        char line[64];
        const int n = snprintf(line, sizeof(line),
                               "[W] " TAG "dropped %lu log line(s) from IRQ context\n", count);
        if (n > 0) {
            Serial.write((const uint8_t *)line, (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1u);
        }
    }
}

// Convenience wrapper (printf-like): no prefix, no newline.
extern "C" void dbg(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    log_line(0, format, ap);
    va_end(ap);
}

// Log function used by the log_x macros.
extern "C" void wg_logf_(char lvl, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_line(lvl, fmt, ap);
    va_end(ap);
}
