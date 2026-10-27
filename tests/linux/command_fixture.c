/* Provisioned static test program, never a helper or authority. The positive
 * test execs an independently pinned child, checks immutable revision content,
 * and exchanges a result through disposable work. Explicit hosted fixture only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void require(int value) { if(!value)_exit(91); }
static void nap(unsigned seconds) {
    struct timespec delay={.tv_sec=seconds};
    while(nanosleep(&delay,&delay)&&errno==EINTR) {}
}
static void result(const char *value) {
    require(write(1,value,strlen(value))==(ssize_t)strlen(value));
}
int main(int argc,char **argv) {
    require(argc==2);
    if(!strcmp(argv[1],"worker")) {
        char data[16]={0};int source=open("changed.txt",O_RDONLY);
        require(source>=0&&read(source,data,sizeof(data))==5&&!memcmp(data,"head\n",5));
        require(close(source)==0);
        int work=openat(4,"child.result",O_WRONLY|O_CREAT|O_EXCL,0600);
        require(work>=0&&write(work,"checked\n",8)==8&&close(work)==0);
        return 0;
    }
    if(!strcmp(argv[1],"positive")) {
        require(getenv("LD_PRELOAD")==NULL&&getenv("PATH")==NULL);
        require(fcntl(3,F_GETFD)==-1&&errno==EBADF);
        require(fcntl(5,F_GETFD)==-1&&errno==EBADF);
        pid_t child=fork();require(child>=0);
        if(child==0) {
            char *args[]={"/usr/bin/uas-command-worker","worker",NULL};
            execve(args[0],args,(char *const[]){NULL});_exit(92);
        }
        int status=0;require(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
        char path[96];const char *temporary=getenv("TMPDIR");require(temporary!=NULL);
        int length=snprintf(path,sizeof(path),"%s/child.result",temporary);
        require(length>0&&(size_t)length<sizeof(path));
        char data[16]={0};int work=open(path,O_RDONLY);
        require(work>=0&&read(work,data,sizeof(data))==8&&!memcmp(data,"checked\n",8));
        require(close(work)==0);result("configured child test passed\n");return 0;
    }
    if(!strcmp(argv[1],"nonzero"))return 7;
    if(!strcmp(argv[1],"timeout")) {
        pid_t child=fork();require(child>=0);
        if(child==0) {nap(20);_exit(0);}
        return 0; /* A zero leader cannot make a surviving child a pass. */
    }
    if(!strcmp(argv[1],"loss")) {
        pid_t child=fork();require(child>=0);
        if(child==0) {nap(20);_exit(0);}
        int fd=openat(4,".ready",O_WRONLY|O_CREAT|O_EXCL,0660);char data[128];
        int size=snprintf(data,sizeof(data),"%ld %ld %ld\n",(long)getppid(),(long)getpid(),(long)child);
        require(fd>=0&&fchmod(fd,0660)==0&&size>0&&(size_t)size<sizeof(data)&&write(fd,data,(size_t)size)==size&&close(fd)==0);
        require(renameat(4,".ready",4,"ready")==0);
        nap(20);return 0;
    }
    if(!strcmp(argv[1],"output")) {
        char data[4096];memset(data,'x',sizeof(data));
        for(unsigned i=0;i<512;i++)require(write(1,data,sizeof(data))==(ssize_t)sizeof(data));
        return 0;
    }
    if(!strcmp(argv[1],"network")) {socket(AF_INET,SOCK_STREAM,0);return 93;}
    if(!strcmp(argv[1],"group-escape")) {setsid();return 93;}
    if(!strcmp(argv[1],"outside-chmod")) {chmod("/uas/gate-work/foreign/sentinel",0777);return 93;}
    if(!strcmp(argv[1],"outside-utime")) {utimensat(AT_FDCWD,"/uas/gate-work/foreign/sentinel",NULL,0);return 93;}
    if(!strcmp(argv[1],"async-owner")) {fcntl(1,F_SETOWN,getppid());return 93;}
    if(!strcmp(argv[1],"async-flags")) {fcntl(1,F_SETFL,O_ASYNC);return 93;}
    if(!strcmp(argv[1],"ioctl-denial")) {
        int on=1;require(ioctl(1,FIOASYNC,&on)==-1&&errno==ENOTTY);
        result("async ioctl denied\n");return 0;
    }
    if(!strcmp(argv[1],"target-write")) {
        require(open("changed.txt",O_WRONLY|O_TRUNC)==-1&&(errno==EROFS||errno==EACCES));
        result("immutable target preserved\n");return 0;
    }
    if(!strcmp(argv[1],"process-limit")) {
        unsigned count=0;int exhausted=0;
        for(;count<32;count++) {
            pid_t child=fork();
            if(child<0) {require(errno==EAGAIN);exhausted=1;break;}
            if(child==0) {nap(1);_exit(0);}
        }
        require(exhausted&&count>0&&count<=5);
        for(unsigned i=0;i<count;i++) {int status;require(waitpid(-1,&status,0)>0&&WIFEXITED(status)&&WEXITSTATUS(status)==0);}
        result("hard shared-UID process ceiling enforced\n");return 0;
    }
    if(!strcmp(argv[1],"memory-limit")) {
        void *large=malloc(80U*1024U*1024U);require(large==NULL&&errno==ENOMEM);
        result("hard per-process address-space ceiling enforced\n");return 0;
    }
    if(!strcmp(argv[1],"work-limit")) {
        int fd=openat(4,"bounded",O_WRONLY|O_CREAT|O_EXCL,0600);require(fd>=0);
        char block[4096]={0};unsigned count=0;
        for(;count<2304;count++) {
            if(count==1024) {
                require(close(fd)==0);fd=openat(4,"bounded-two",O_WRONLY|O_CREAT|O_EXCL,0600);require(fd>=0);
            }
            ssize_t amount=write(fd,block,sizeof(block));
            if(amount<0) {require(errno==ENOSPC);result("hard work quota enforced\n");return 0;}
            require(amount==(ssize_t)sizeof(block));
        }
        return 94;
    }
    return 95;
}
