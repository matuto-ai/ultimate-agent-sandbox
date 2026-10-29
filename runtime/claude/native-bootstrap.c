/* Fixed SDK spawn wrapper: FD3 rendezvous, untouched SDK stdin/stdout/stderr.
 * Same task execs pinned Claude. No fork, shell, provider credential or PID claim.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
extern char **environ;
static void fail(void) { _exit(125); }
int main(int argc, char **argv) {
    if (argc < 4 || argc > 128 || strcmp(argv[2], "/opt/uas/claude/claude")
        || argv[1][0] != '/' || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) fail();
    if (prctl(PR_SET_DUMPABLE,0) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) fail();
    alarm(15);
    unsigned char packet[36] = {'U','A','S','1'};
    size_t n = 0;
    while (n < 32) {
        ssize_t got = read(3,packet+4+n,32-n);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) fail();
        n += (size_t)got;
    }
    if (close(3)) fail();
    int peer=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if (peer < 0) fail();
    struct sockaddr_un address={.sun_family=AF_UNIX};
    strcpy(address.sun_path,argv[1]);
    if (connect(peer,(struct sockaddr *)&address,sizeof(address))
        || send(peer,packet,sizeof(packet),MSG_NOSIGNAL) != (ssize_t)sizeof(packet)) fail();
    char reply[32];
    ssize_t count=recv(peer,reply,sizeof(reply),0);
    if (count != 14 || memcmp(reply,"UAS-RELEASE-1\n",14)) fail();
    /* Keep the root lifetime channel at FD3; no CLI records are trusted here.
     * MCP subprocess creates its own separately admitted FD3. */
    if (peer != 3 && dup2(peer,3) != 3) fail();
    if (fcntl(3,F_SETFD,0) || close_range(4,~0U,0)) fail();
    alarm(0);
    execve(argv[2],argv+2,environ);
    fail();
}
