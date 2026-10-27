/* Fixed distinct-UID Git worker bootstrap. No shell or caller-selected exec. */
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
#ifndef UAS_GIT_ENDPOINT
#define UAS_GIT_ENDPOINT "/uas/git/worker.sock"
#endif
static void fail(void) { _exit(125); }
static void exact_read(int fd, void *value, size_t count) {
    char *p=value;
    while(count) {
        ssize_t got=read(fd,p,count);
        if(got<0 && errno==EINTR) continue;
        if(got<=0) fail();
        p+=got;count-=(size_t)got;
    }
}
int main(int argc,char **argv) {
    if(prctl(PR_SET_DUMPABLE,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) fail();
    if(argc!=2||(strcmp(argv[1],"seat-a")&&strcmp(argv[1],"seat-b"))) fail();
    if(getuid()!=65530||getgid()!=65532) fail();
    alarm(15);
    int channel=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if(channel<0) fail();
    struct sockaddr_un address={.sun_family=AF_UNIX};
    if(strlen(UAS_GIT_ENDPOINT)>=sizeof(address.sun_path)) fail();
    strcpy(address.sun_path,UAS_GIT_ENDPOINT);
    if(connect(channel,(struct sockaddr*)&address,sizeof(address))) fail();
    unsigned char hello[36]={'U','A','S','1'};
    exact_read(STDIN_FILENO,hello+4,32);
    if(send(channel,hello,36,MSG_NOSIGNAL)!=36) fail();
    char response[32];
    ssize_t got=recv(channel,response,sizeof(response),0);
    if(got!=14||memcmp(response,"UAS-RELEASE-1\n",14)) fail();
    if(channel!=3&&dup2(channel,3)!=3) fail();
    if(fcntl(3,F_SETFD,0)||close_range(4,~0U,0)) fail();
    char *environment[]={"PATH=/usr/bin:/bin","LANG=C.UTF-8",NULL};
    char *arguments[]={"/usr/bin/python3","-I",UAS_ROOT "/runtime/git/worker.py",NULL};
    alarm(0);
    execve(arguments[0],arguments,environment);
    fail();
}
