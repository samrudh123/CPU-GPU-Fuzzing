/*
 * magic_mutator.c — a minimal, structure-aware AFL++ custom mutator.
 *
 * It is written to pair with the example target.c: that target only does
 * anything once the input starts with the 4 magic bytes "FUZZ", and has
 * bugs gated behind a specific length byte (0xFF) and a "BOM" command.
 * A blind mutator wastes most of its energy never passing the magic gate;
 * this one biases mutations toward the structure the target expects, so it
 * reaches the planted bugs much faster. That is exactly what custom mutators
 * are for: encoding knowledge of the input format.
 *
 * Note: this uses `void *afl` instead of `afl_state_t *afl`, so it compiles
 * standalone with NO AFL++ headers. If you want access to AFL++'s internal
 * state, include "afl-fuzz.h" (installed under $CONDA_PREFIX/include/afl)
 * and change the type — but then you must rebuild this whenever you update
 * AFL++, because that struct can change between versions.
 *
 * Build:
 *     clang -shared -fPIC -O3 -o magic_mutator.so magic_mutator.c
 *
 * Use:
 *     export AFL_CUSTOM_MUTATOR_LIBRARY="$PWD/magic_mutator.so"
 *     # optional: disable built-in mutations and ONLY use this one
 *     # export AFL_CUSTOM_MUTATOR_ONLY=1
 *     afl-fuzz -i input -o output -m none -- ./target_fuzz @@
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct my_mutator {
  uint8_t *buf;        /* our own output buffer; must outlive the call   */
  size_t   buf_size;   /* current capacity of buf                        */
} my_mutator_t;

/* Called once at startup. Allocate per-mutator state here. */
my_mutator_t *afl_custom_init(void *afl, unsigned int seed) {
  (void)afl;
  srand(seed);                       /* AFL++ gives us a deterministic seed */
  my_mutator_t *m = calloc(1, sizeof(my_mutator_t));
  return m;                          /* NULL on failure is handled by AFL++ */
}

/* Grow our internal buffer to hold at least `need` bytes. */
static uint8_t *ensure(my_mutator_t *m, size_t need) {
  if (m->buf_size < need) {
    uint8_t *p = realloc(m->buf, need);
    if (!p) return NULL;
    m->buf = p;
    m->buf_size = need;
  }
  return m->buf;
}

/*
 * The core mutation function. AFL++ hands us the current test case (in_buf,
 * in_len); we produce a mutated version, point *out_buf at it, and return
 * its length. Returning 0 tells AFL++ to skip this one. The buffer we point
 * to must stay valid after we return, so it lives in our struct, never on
 * the stack. add_buf is a second queue entry offered for splicing; we ignore
 * it here.
 */
size_t afl_custom_fuzz(my_mutator_t *m,
                       uint8_t *in_buf, size_t in_len,
                       uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_len,
                       size_t max_size) {
  (void)add_buf; (void)add_len;

  size_t out_len = in_len < 8 ? 8 : in_len;   /* need room for the structure */
  if (out_len > max_size) out_len = max_size;
  if (out_len < 8) { *out_buf = in_buf; return in_len; }  /* too small, pass through */

  uint8_t *out = ensure(m, out_len);
  if (!out) { *out_buf = in_buf; return in_len; }         /* alloc fail, pass through */

  /* Start from the original input. */
  memset(out, 0, out_len);
  memcpy(out, in_buf, in_len < out_len ? in_len : out_len);

  /* (a) Some broad random havoc first, so we still explore widely. */
  for (int i = 0; i < 4; i++) {
    size_t pos = (size_t)rand() % out_len;
    out[pos] ^= (uint8_t)(rand() & 0xff);
  }

  /* (b) Re-assert the structure AFTER havoc so it usually survives. */

  /* 95% of the time, satisfy the "FUZZ" magic gate. */
  if (rand() % 100 < 95) memcpy(out, "FUZZ", 4);

  /* 30% of the time, aim byte 4 at the overflow / OOB-read paths. */
  if (rand() % 100 < 30)
    out[4] = (rand() % 100 < 50) ? 0xFF : (uint8_t)(20 + rand() % 200);

  /* 10% of the time, line up the deeper "BOM" command. */
  if (rand() % 100 < 10) { out[5] = 'B'; out[6] = 'O'; out[7] = 'M'; }

  *out_buf = out;
  return out_len;
}

/* Called once at shutdown. Free everything we allocated. */
void afl_custom_deinit(my_mutator_t *m) {
  if (m) {
    free(m->buf);
    free(m);
  }
}
