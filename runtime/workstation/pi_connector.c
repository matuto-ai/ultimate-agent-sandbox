/* Fixed pre-runtime rendezvous; no shell, proxy, configuration loader or fork.
 * Production compilation uses the paths below. Test builds override UAS_ROOT
 * only to prove the bootstrap syscall contract, never native Pi qualification.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#ifndef UAS_ROOT
#define UAS_ROOT "/opt/uas"
#endif
#ifndef UAS_WORKSPACE
#define UAS_WORKSPACE "/uas/workspace"
#endif
#ifndef UAS_ENDPOINT
#define UAS_ENDPOINT "/run/uas-peer/peer.sock"
#endif

static void fail(void) { _exit(125); }
static void exact_read(int fd, void *target, size_t size) {
    char *p = target;
    while (size) {
        ssize_t count = read(fd, p, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail();
        p += count; size -= (size_t)count;
    }
}
int main(int argc, char **argv) {
    /* This precedes challenge input and all runtime/user-state loading. */
    if (prctl(PR_SET_DUMPABLE, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail();
    if (argc != 2 || (strcmp(argv[1], "seat-a") && strcmp(argv[1], "seat-b"))) fail();
    alarm(15);
    int peer = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (peer < 0) fail();
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(UAS_ENDPOINT) >= sizeof(address.sun_path)) fail();
    strcpy(address.sun_path, UAS_ENDPOINT);
    if (connect(peer, (struct sockaddr *)&address, sizeof(address))) fail();
    unsigned char packet[36] = {'U', 'A', 'S', '1'};
    exact_read(STDIN_FILENO, packet + 4, 32);
    if (send(peer, packet, sizeof(packet), MSG_NOSIGNAL) != sizeof(packet)) fail();
    char response[32];
    ssize_t count = recv(peer, response, sizeof(response), 0);
    if (count != 14 || memcmp(response, "UAS-RELEASE-1\n", 14)) fail();
    /* The same task and open description continue through execve. */
    if (peer != 3 && dup2(peer, 3) != 3) fail();
    if (fcntl(3, F_SETFD, 0) || fcntl(3, F_SETFL, O_NONBLOCK)) fail();
    if (close_range(4, ~0U, 0)) fail();
    const char *home = !strcmp(argv[1], "seat-a") ? "/uas/runtime/seat-a" : "/uas/runtime/seat-b";
    char home_env[128], agent_env[160], sessions[160];
    if (snprintf(home_env, sizeof(home_env), "HOME=%s", home) >= (int)sizeof(home_env)
        || snprintf(agent_env, sizeof(agent_env), "PI_CODING_AGENT_DIR=%s/agent", home) >= (int)sizeof(agent_env)
        || snprintf(sessions, sizeof(sessions), "%s/sessions", home) >= (int)sizeof(sessions)) fail();
    char *environment[] = {"PATH=" UAS_ROOT "/node/bin:/usr/bin:/bin", home_env, agent_env,
        "LANG=C.UTF-8", "PI_OFFLINE=1", "UAS_PI_PEER_FD=3",
        "NODE_OPTIONS=--import=" UAS_ROOT "/tests/pi/network-guard.mjs",
        "UAS_PI_FAUX_MODULE=" UAS_ROOT "/pi/node_modules/@earendil-works/pi-ai/dist/providers/faux.js", NULL};
    char *arguments[] = {UAS_ROOT "/node/bin/node",
        UAS_ROOT "/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
        "--mode", "rpc", "--no-builtin-tools", "--no-extensions", "--no-skills",
        "--no-prompt-templates", "--no-themes", "-e", UAS_ROOT "/runtime/pi/extension.mjs",
        "-e", UAS_ROOT "/tests/pi/provider.mjs", "--provider", "faux", "--model", "faux-1",
        "--session-dir", sessions, NULL};
    if (chdir(UAS_WORKSPACE)) fail();
    alarm(0);
    execve(arguments[0], arguments, environment);
    fail();
}
