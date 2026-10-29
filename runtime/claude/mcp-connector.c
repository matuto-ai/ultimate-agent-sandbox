/* Fixed native-Claude descendant helper. No bearer identity or client seat claim.
 * Supervisor authenticates actual sender lineage before releasing this task.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
static void fail(void) { _exit(125); }
int main(int argc,char **argv) {
    if (argc != 2 || argv[1][0] != '/' || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) fail();
    if (prctl(PR_SET_DUMPABLE,0) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) fail();
    alarm(15);
    int peer=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if (peer < 0) fail();
    struct sockaddr_un address={.sun_family=AF_UNIX}; strcpy(address.sun_path,argv[1]);
    const char hello[]="UAS-CLAUDE-MCP-1\n";
    if (connect(peer,(struct sockaddr *)&address,sizeof(address))
        || send(peer,hello,sizeof(hello)-1,MSG_NOSIGNAL) != (ssize_t)(sizeof(hello)-1)) fail();
    char reply[32]; ssize_t count=recv(peer,reply,sizeof(reply),0);
    if (count != 14 || memcmp(reply,"UAS-RELEASE-1\n",14)) fail();
    /* Same task opens the private Forge channel; Hub never receives FD4. */
    int forge=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    const char forge_hello[]="UAS-CLAUDE-FORGE-1\n";
    if (forge < 0 || connect(forge,(struct sockaddr *)&address,sizeof(address))
        || send(forge,forge_hello,sizeof(forge_hello)-1,MSG_NOSIGNAL) != (ssize_t)(sizeof(forge_hello)-1)) fail();
    count=recv(forge,reply,sizeof(reply),0);
    if (count != 20 || memcmp(reply,"UAS-FORGE-RELEASE-1\n",20)) fail();
    /* Avoid overwriting either source descriptor while assigning fixed FDs. */
    int peer_copy=fcntl(peer,F_DUPFD_CLOEXEC,5), forge_copy=fcntl(forge,F_DUPFD_CLOEXEC,5);
    if (peer_copy < 0 || forge_copy < 0 || dup2(peer_copy,3)!=3 || dup2(forge_copy,4)!=4) fail();
    if (fcntl(4,F_SETFD,0) || fcntl(4,F_SETFL,O_NONBLOCK)) fail();
    peer=3;
    if (peer != 3 && dup2(peer,3) != 3) fail();
    if (fcntl(3,F_SETFD,0) || fcntl(3,F_SETFL,O_NONBLOCK) || close_range(5,~0U,0)) fail();
    char *env[]={"PATH=/opt/uas/node/bin:/usr/bin:/bin","LANG=C.UTF-8",NULL};
    char *args[]={"/opt/uas/node/bin/node","/opt/uas/runtime/claude/mcp-server.mjs",NULL};
    alarm(0); execve(args[0],args,env); fail();
}
