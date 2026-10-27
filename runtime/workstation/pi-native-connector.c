/* Opt-in native Pi bootstrap; compile static, stack protected, no exec stack.
 * Supervisor supplies typed non-secret argv; no shell, config loader or fork.
 * Same task crosses challenge/release/exec, retaining only the peer FD.
 * This source does not qualify an image, provider, mount or kernel boundary.
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

static void fail(void) { _exit(125); }
static int safe_path(const char *p) {
    size_t n = strlen(p);
    if (n < 2 || n > 512 || p[0] != '/' || p[n-1] == '/') return 0;
    for (size_t i = 0; i < n; i++) if ((unsigned char)p[i] < 33 || p[i] == 127) return 0;
    if (strstr(p, "//") || strstr(p, "/../") || strstr(p, "/./")) return 0;
    return strcmp(p+n-2,"/.") && (n<3 || strcmp(p+n-3,"/.."));
}
static int choice(const char *p) {
    size_t n = strlen(p);
    if (!n || n > 128 || !((p[0]>='A'&&p[0]<='Z')||(p[0]>='a'&&p[0]<='z')||(p[0]>='0'&&p[0]<='9'))) return 0;
    for (size_t i=0;i<n;i++) if (!((p[i]>='A'&&p[i]<='Z')||(p[i]>='a'&&p[i]<='z')||(p[i]>='0'&&p[i]<='9')||strchr("._:/-",p[i]))) return 0;
    return 1;
}
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
    if (argc != 7 || !safe_path(argv[1]) || !safe_path(argv[2]) || !safe_path(argv[3])
        || !safe_path(argv[4]) || !choice(argv[5]) || !choice(argv[6])) fail();
    size_t home_len = strlen(argv[3]);
    if (strncmp(argv[4],argv[3],home_len) || strncmp(argv[4]+home_len,"/contexts/",10)) fail();
    alarm(15);
    int peer = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (peer < 0) fail();
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(argv[1]) >= sizeof(address.sun_path)) fail();
    strcpy(address.sun_path, argv[1]);
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
    char home_env[520], agent_env[560];
    if (snprintf(home_env,sizeof(home_env),"HOME=%s",argv[3]) >= (int)sizeof(home_env)
        || snprintf(agent_env,sizeof(agent_env),"PI_CODING_AGENT_DIR=%s/agent",argv[3]) >= (int)sizeof(agent_env)) fail();
    char *environment[] = {"PATH=" UAS_ROOT "/node/bin:/usr/bin:/bin",home_env,agent_env,
        "LANG=C.UTF-8","UAS_PI_PEER_FD=3",NULL};
    char *arguments[] = {UAS_ROOT "/node/bin/node",
        UAS_ROOT "/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
        "--mode","rpc","--no-extensions","--no-skills","--no-prompt-templates","--no-themes",
        "-e",UAS_ROOT "/runtime/pi/extension.mjs","--provider",argv[5],"--model",argv[6],
        "--session-dir",argv[4],NULL};
    if (chdir(argv[2])) fail();
    alarm(0);
    execve(arguments[0], arguments, environment);
    fail();
}
