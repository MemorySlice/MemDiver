/* tests/fixtures/aes_sample.c
 * Sample process with AES-256 key in a known struct layout.
 * For forensic testing - keys are pinned in heap-allocated struct.
 *
 * Build: cc -O0 -o aes_sample aes_sample.c
 * Usage: ./aes_sample
 * Output: MEMDIVER_PID=<pid>
 *         MEMDIVER_KEY=<hex>
 *         MEMDIVER_IV=<hex>
 *         MEMDIVER_KEY_ADDR=<hex_addr>
 *         MEMDIVER_STRUCT_ADDR=<hex_addr>
 *         MEMDIVER_READY=1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

/* AES context struct - mimics a simplified crypto library layout.
 * The key is at a KNOWN offset within this struct.
 * ASLR changes the struct's address, but not the internal layout. */
struct aes_context {
    /* Offset 0x00: Pre-key structural fields (anchors) */
    unsigned int magic;          /* 0x41455332 = "AES2" */
    unsigned int key_bits;       /* 256 */
    unsigned int algorithm_id;   /* 14 = AES-256-CBC */
    unsigned int block_size;     /* 16 */

    /* Offset 0x10: The actual AES-256 key */
    unsigned char key[32];

    /* Offset 0x30: The IV */
    unsigned char iv[16];

    /* Offset 0x40: Post-key structural fields (anchors) */
    unsigned int rounds;         /* 14 for AES-256 */
    unsigned int initialized;    /* 1 */
    unsigned int pad_mode;       /* 0 = none */
    unsigned int sentinel;       /* 0xDEADBEEF */

    /* Offset 0x50: Round keys (expanded, 240 bytes for AES-256) */
    unsigned char round_keys[240];
};

static volatile int running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

static void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s=", label);
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* Simple key expansion placeholder (not real AES, just fills round_keys
   deterministically from the key so they form structural anchors) */
static void expand_key(struct aes_context *ctx) {
    unsigned char temp[32];
    memcpy(temp, ctx->key, 32);
    for (int i = 0; i < 240; i++) {
        ctx->round_keys[i] = temp[i % 32] ^ (unsigned char)(i * 0x37 + 0x5A);
    }
}

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    /* Allocate on heap - ASLR will randomize this address */
    struct aes_context *ctx = (struct aes_context *)malloc(sizeof(struct aes_context));
    if (!ctx) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    memset(ctx, 0, sizeof(struct aes_context));

    /* Fill structural anchors */
    ctx->magic = 0x41455332;      /* "AES2" */
    ctx->key_bits = 256;
    ctx->algorithm_id = 14;
    ctx->block_size = 16;
    ctx->rounds = 14;
    ctx->initialized = 1;
    ctx->pad_mode = 0;
    ctx->sentinel = 0xDEADBEEF;

    /* Generate random key and IV from /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open /dev/urandom\n");
        free(ctx);
        return 1;
    }
    read(fd, ctx->key, 32);
    read(fd, ctx->iv, 16);
    close(fd);

    /* Expand key (fills round_keys deterministically from key) */
    expand_key(ctx);

    /* Output structured info for driver script */
    printf("MEMDIVER_PID=%d\n", getpid());
    print_hex("MEMDIVER_KEY", ctx->key, 32);
    print_hex("MEMDIVER_IV", ctx->iv, 16);
    printf("MEMDIVER_KEY_ADDR=0x%lx\n", (unsigned long)&ctx->key[0]);
    printf("MEMDIVER_STRUCT_ADDR=0x%lx\n", (unsigned long)ctx);
    printf("MEMDIVER_KEY_OFFSET=0x%lx\n", (unsigned long)((char *)&ctx->key[0] - (char *)ctx));
    printf("MEMDIVER_STRUCT_SIZE=%lu\n", (unsigned long)sizeof(struct aes_context));
    printf("MEMDIVER_READY=1\n");
    fflush(stdout);

    /* Keep running until signaled */
    while (running) {
        /* Touch the key periodically to prevent optimization */
        volatile unsigned char check = 0;
        for (int i = 0; i < 32; i++)
            check ^= ctx->key[i];
        (void)check;
        sleep(5);
    }

    /* Don't free immediately - forensic tools may still be reading */
    free(ctx);
    return 0;
}
