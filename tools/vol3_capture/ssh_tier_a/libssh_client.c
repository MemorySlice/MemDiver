/* libssh_client.c -- Tier A SSH ground truth: a libssh client that completes one
 * key exchange with the paramiko ground-truth server (gt_server.py), runs one
 * exec, then stays connected and idle so its session keys are live at dump time.
 *
 * Fixed algorithms: curve25519-sha256 + aes256-ctr + hmac-sha2-256, password auth.
 * Build (in the guest): gcc -O0 -g -o libssh_client libssh_client.c -lssh
 * Usage: libssh_client <port> [idle_seconds]       (default idle: 7 days)
 * Prints "negotiated ..." and "READY pid=<pid> libssh=<version>" on stdout. */
#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void die(ssh_session s, const char *what) {
    fprintf(stderr, "%s: %s\n", what, ssh_get_error(s));
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port> [idle_seconds]\n", argv[0]); return 2; }
    unsigned int port = (unsigned int)atoi(argv[1]);
    unsigned int idle_s = argc > 2 ? (unsigned int)atoi(argv[2]) : 7u * 24u * 3600u;
    ssh_session s = ssh_new();
    ssh_options_set(s, SSH_OPTIONS_HOST, "127.0.0.1");
    ssh_options_set(s, SSH_OPTIONS_PORT, &port);
    ssh_options_set(s, SSH_OPTIONS_USER, "testuser");
    ssh_options_set(s, SSH_OPTIONS_KEY_EXCHANGE, "curve25519-sha256@libssh.org,curve25519-sha256");
    ssh_options_set(s, SSH_OPTIONS_CIPHERS_C_S, "aes256-ctr");
    ssh_options_set(s, SSH_OPTIONS_CIPHERS_S_C, "aes256-ctr");
    ssh_options_set(s, SSH_OPTIONS_HMAC_C_S, "hmac-sha2-256");
    ssh_options_set(s, SSH_OPTIONS_HMAC_S_C, "hmac-sha2-256");
    ssh_options_set(s, SSH_OPTIONS_HOSTKEYS, "rsa-sha2-256,rsa-sha2-512");
    if (ssh_connect(s) != SSH_OK) die(s, "connect");
    if (ssh_userauth_password(s, NULL, "password") != SSH_AUTH_SUCCESS) die(s, "auth");
    printf("negotiated kex=%s cipher_out=%s cipher_in=%s hmac_out=%s hmac_in=%s\n",
           ssh_get_kex_algo(s), ssh_get_cipher_out(s), ssh_get_cipher_in(s),
           ssh_get_hmac_out(s), ssh_get_hmac_in(s));
    ssh_channel ch = ssh_channel_new(s);
    if (ssh_channel_open_session(ch) != SSH_OK) die(s, "open");
    if (ssh_channel_request_exec(ch, "echo memdiver-libssh-session") != SSH_OK) die(s, "exec");
    char buf[256];
    int n;
    while ((n = ssh_channel_read(ch, buf, sizeof buf - 1, 0)) > 0) {
        buf[n] = 0;
        printf("exec output: %s", buf);
    }
    ssh_channel_send_eof(ch);
    ssh_channel_close(ch);
    ssh_channel_free(ch);
    printf("READY pid=%d libssh=%s\n", getpid(), ssh_version(0));
    fflush(stdout);
    sleep(idle_s);
    ssh_disconnect(s);
    ssh_free(s);
    return 0;
}
