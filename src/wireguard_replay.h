/*
 * Anti-replay window for WireGuard transport data: a ring bitmap in the
 * style of RFC 6479 covering the last 8192 counters. Counter zero is
 * accepted once from a fresh state, so the first data packet of a session
 * is not lost when no keepalive preceded it.
 */
#ifndef WIREGUARD_REPLAY_H
#define WIREGUARD_REPLAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WIREGUARD_REPLAY_WORD_BITS 32u
#define WIREGUARD_REPLAY_BITMAP_BITS 8192u
#define WIREGUARD_REPLAY_WORD_COUNT                                            \
  (WIREGUARD_REPLAY_BITMAP_BITS / WIREGUARD_REPLAY_WORD_BITS)
#define WIREGUARD_REPLAY_WINDOW_BITS                                           \
  (WIREGUARD_REPLAY_BITMAP_BITS - WIREGUARD_REPLAY_WORD_BITS)
#define WIREGUARD_REPLAY_REJECT_AFTER_MESSAGES                                 \
  (UINT64_MAX - (UINT64_C(1) << 13u))

typedef struct {
  uint32_t bitmap[WIREGUARD_REPLAY_WORD_COUNT];
  uint64_t counter;
} wireguard_replay_state_t;

static inline void
wireguard_replay_reset(wireguard_replay_state_t *replay_state) {
  size_t index;
  if (replay_state == NULL) {
    return;
  }
  for (index = 0u; index < WIREGUARD_REPLAY_WORD_COUNT; ++index) {
    replay_state->bitmap[index] = 0u;
  }
  replay_state->counter = 0u;
}

static inline bool
wireguard_replay_check(wireguard_replay_state_t *replay_state,
                       uint64_t sequence) {
  uint64_t received_counter;
  uint64_t word_index;

  if (replay_state == NULL ||
      sequence >= WIREGUARD_REPLAY_REJECT_AFTER_MESSAGES ||
      replay_state->counter >= WIREGUARD_REPLAY_REJECT_AFTER_MESSAGES + 1u) {
    return false;
  }

  /* Store counter + 1 so the all-zero state can accept sequence zero once. */
  received_counter = sequence + 1u;
  if (received_counter + WIREGUARD_REPLAY_WINDOW_BITS < replay_state->counter) {
    return false;
  }

  word_index = received_counter / WIREGUARD_REPLAY_WORD_BITS;
  if (received_counter > replay_state->counter) {
    const uint64_t current_word =
        replay_state->counter / WIREGUARD_REPLAY_WORD_BITS;
    uint64_t words_to_clear = word_index - current_word;
    uint64_t offset;
    if (words_to_clear > WIREGUARD_REPLAY_WORD_COUNT) {
      words_to_clear = WIREGUARD_REPLAY_WORD_COUNT;
    }
    for (offset = 1u; offset <= words_to_clear; ++offset) {
      replay_state->bitmap[(current_word + offset) &
                           (WIREGUARD_REPLAY_WORD_COUNT - 1u)] = 0u;
    }
    replay_state->counter = received_counter;
  }

  {
    const uint32_t bit = UINT32_C(1)
                         << (uint32_t)(received_counter &
                                       (WIREGUARD_REPLAY_WORD_BITS - 1u));
    uint32_t *const word =
        &replay_state->bitmap[word_index & (WIREGUARD_REPLAY_WORD_COUNT - 1u)];
    if ((*word & bit) != 0u) {
      return false;
    }
    *word |= bit;
  }
  return true;
}

#endif
