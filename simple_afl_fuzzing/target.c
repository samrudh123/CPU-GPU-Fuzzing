/*
 * target.c — a deliberately vulnerable program for practicing with AFL++.
 *
 * It reads an input file (passed as argv[1], which is what the `@@`
 * placeholder in afl-fuzz provides) and "parses" it. The parsing logic
 * contains several intentional bugs of increasing depth so you can watch
 * AFL++ discover them. Compile with AddressSanitizer so the memory bugs
 * actually crash:
 *
 *     export AFL_USE_ASAN=1
 *     afl-clang-fast -o target_fuzz target.c
 *     afl-fuzz -i input -o output -m none -- ./target_fuzz @@
 *
 * DO NOT use code like this anywhere real — every "bug" here is on purpose.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Reads the whole file into a heap buffer. Caller must free().
 * Sets *out_len to the number of bytes read. Returns NULL on error. */
static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *out_len = got;
    return buf;
}

static void parse(const unsigned char *data, size_t len) {
    /* The input must start with the 4-byte magic "FUZZ" to reach the
     * interesting code. This is a shallow gate AFL++ learns quickly by
     * observing coverage as it mutates bytes 0-3. */
    if (len < 4) return;
    if (memcmp(data, "FUZZ", 4) != 0) return;

    /* BUG 1 (stack buffer overflow): byte 4 is treated as a length, and we
     * copy that many bytes from the input into a fixed 16-byte stack buffer
     * with no bounds check. Any length > 16 smashes the stack — ASAN flags
     * it as a stack-buffer-overflow. */
    if (len < 5) return;
    uint8_t claimed_len = data[4];
    char small[16];
    size_t avail = len - 5;
    size_t copy = claimed_len < avail ? claimed_len : avail;
    memcpy(small, data + 5, copy);   /* <-- overflow when copy > 16 */
    small[copy % sizeof(small)] = '\0';

    /* BUG 2 (out-of-bounds read): if byte 4 happens to be 0xFF, we read a
     * byte well past the end of the buffer. A deeper path AFL++ reaches only
     * after also setting that specific byte value. */
    if (claimed_len == 0x41) {
        volatile unsigned char x = data[len + 100];  /* <-- OOB read */
        (void)x;
    }

    /* BUG 3 (null-pointer deref): a multi-byte "command" gate, harder to hit
     * because it needs several specific bytes lined up. Good for seeing how
     * coverage guidance grinds toward rare paths. */
    if (len >= 8 && data[5] == 'B' && data[6] == 'O' && data[7] == 'M') {
        char *p = NULL;
        *p = 1;   /* <-- crash */
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    size_t len = 0;
    unsigned char *data = read_file(argv[1], &len);
    if (!data) return 1;

    parse(data, len);

    free(data);
    return 0;
}
