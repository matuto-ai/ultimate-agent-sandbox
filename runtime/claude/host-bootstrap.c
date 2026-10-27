/* Exact Engine task handshake before same-task exec into the SDK cleanup host.
 * This identity is NEVER the Claude Participant. Child has a second rendezvous.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
static void fail(void) { _exit(125); }
int main(int argc,char **argv) {
    if (argc!=9 || argv[1][0]!='/' || strlen(argv[1])>=sizeof(((struct sockaddr_un *)0)->sun_path)) fail();
    if (prctl(PR_SET_DUMPABLE,0) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) fail();
    alarm(15);
    unsigned char packet[36]={'U','A','S','1'}; size_t offset=0;
    while(offset<32) { ssize_t n=read(0,packet+4+offset,32-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) fail();
        offset+=(size_t)n; }
    int peer=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0); if(peer<0) fail();
    struct sockaddr_un address={.sun_family=AF_UNIX}; strcpy(address.sun_path,argv[1]);
    if(connect(peer,(struct sockaddr *)&address,sizeof(address)) || send(peer,packet,sizeof(packet),MSG_NOSIGNAL)!=(ssize_t)sizeof(packet)) fail();
    char response[32]; ssize_t n=recv(peer,response,sizeof(response),0);
    if(n!=14 || memcmp(response,"UAS-RELEASE-1\n",14)) fail();
    if(close_range(3,~0U,0)) fail();
    char *env[]={"PATH=/opt/uas/node/bin:/usr/bin:/bin","LANG=C.UTF-8",NULL};
    char *args[]={"/opt/uas/node/bin/node","/opt/uas/runtime/claude/native-host.mjs",
        argv[2],argv[3],argv[1],argv[4],argv[5],argv[6],argv[7],argv[8],NULL};
    alarm(0); execve(args[0],args,env); fail();
}
