/* Build STATIC. Never execute a dynamic bootstrap: Docker Env:[] does not
 * remove inherited LD_PRELOAD. This fixed bootstrap never loads project code,
 * NSS, locale, plugins or configuration. No argv/env/session configuration.
 * Source profile only: qualification must verify immutable binary hashes,
 * readonly image/mounts, mapped UID, endpoint/outer confinement and all denials.
 */
#define _GNU_SOURCE
#include "artifact_protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/openat2.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static void fail(void) { _exit(125); }
static void exact_read(int fd, unsigned char *p, size_t size) {
    while(size) {
        ssize_t n=read(fd,p,size);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)fail();
        p+=n;size-=(size_t)n;
    }
}
static void lower(int resource, rlim_t bound) {
    struct rlimit value;
    if(getrlimit(resource,&value))fail();
    if(value.rlim_max<bound)bound=value.rlim_max;
    value.rlim_cur=value.rlim_max=bound;
    if(setrlimit(resource,&value))fail();
}
static void identity(void) {
    gid_t groups[AG_MAX_FDS];
    int n=getgroups(AG_MAX_FDS,groups);
    if(getuid()!=AG_UID||geteuid()!=AG_UID||getgid()!=AG_UID||getegid()!=AG_UID||n<0)fail();
    for(int i=0;i<n;i++)if(groups[i]!=AG_UID)fail();
    struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
    struct __user_cap_data_struct data[2]={{0},{0}};
    if(syscall(SYS_capget,&header,data))fail();
    for(int i=0;i<2;i++)if(data[i].effective||data[i].permitted||data[i].inheritable)fail();
}
static int open_beneath(int parent,const char *path,int flags,uint64_t resolve) {
    struct open_how how={.flags=(uint64_t)flags,.resolve=resolve};
    return (int)syscall(SYS_openat2,parent,path,&how,sizeof(how));
}
static void endpoint_identity(struct stat *directory,struct stat *node) {
    if(lstat("/uas/gate",directory)||lstat(AG_ENDPOINT,node)
       ||!S_ISDIR(directory->st_mode)||!S_ISSOCK(node->st_mode)
       ||directory->st_uid!=AG_SUPERVISOR_UID||node->st_uid!=AG_SUPERVISOR_UID
       ||directory->st_gid!=AG_UID||node->st_gid!=AG_UID
       ||(directory->st_mode&07777)!=0710||(node->st_mode&07777)!=0620)fail();
}
int main(int argc,char **argv) {
    (void)argv;
    if(clearenv()||argc!=1)fail();
    /* alarm(2), unlike POSIX timer_create timers, survives execve. Force the
     * default fatal action and unblock all signals before arming. No cancel,
     * rearm or SIGALRM handler exists; the final evaluator filter denies them.
     * Delivery still depends on kernel scheduling; exit must be confirmed.
     */
    struct sigaction action={.sa_handler=SIG_DFL};sigset_t empty;
    if(sigemptyset(&action.sa_mask)||sigemptyset(&empty)
       ||sigaction(SIGALRM,&action,NULL)||sigprocmask(SIG_SETMASK,&empty,NULL))fail();
    alarm(AG_WALL_SECONDS);
    if(prctl(PR_SET_DUMPABLE,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))fail();
    identity();
    lower(RLIMIT_AS,AG_MEMORY_BYTES);lower(RLIMIT_CPU,AG_CPU_SECONDS);
    lower(RLIMIT_NOFILE,AG_MAX_FDS);lower(RLIMIT_CORE,0);lower(RLIMIT_FSIZE,0);
    lower(RLIMIT_NPROC,1);lower(RLIMIT_STACK,8U*1024U*1024U);
    if(close_range(3,~0U,0))fail();
    struct stat before_dir,before_node,after_dir,after_node;
    endpoint_identity(&before_dir,&before_node);
    int peer=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if(peer<0)fail();
    struct sockaddr_un address={.sun_family=AF_UNIX};
    memcpy(address.sun_path,AG_ENDPOINT,sizeof(AG_ENDPOINT));
    if(connect(peer,(struct sockaddr*)&address,sizeof(address)))fail();
    struct ucred owner;socklen_t owner_length=sizeof(owner);
    if(getsockopt(peer,SOL_SOCKET,SO_PEERCRED,&owner,&owner_length)
       ||owner_length!=sizeof(owner)||owner.uid!=AG_SUPERVISOR_UID
       ||owner.gid!=AG_SUPERVISOR_UID)fail();
    endpoint_identity(&after_dir,&after_node);
    if(before_dir.st_dev!=after_dir.st_dev||before_dir.st_ino!=after_dir.st_ino
       ||before_node.st_dev!=after_node.st_dev||before_node.st_ino!=after_node.st_ino)fail();
    unsigned char hello[36]={'A','G','H','1'};exact_read(STDIN_FILENO,hello+4,32);
    if(send(peer,hello,sizeof(hello),MSG_NOSIGNAL)!=(ssize_t)sizeof(hello))fail();
    /* No recvmsg, descriptor passing or target path received. The only setup
     * value is a fixed-width Supervisor-owned target ID after held-task bind.
     */
    unsigned char release[37];ssize_t n=recv(peer,release,sizeof(release),0);
    if(n!=36||memcmp(release,"AGR1",4))fail();
    char target[33];
    for(unsigned i=0;i<32;i++) {
        unsigned char c=release[4+i];
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))fail();
        target[i]=(char)c;
    }
    target[32]=0;
    int root=open("/",O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(root<0)fail();
    uint64_t containment=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS;
    int targets=open_beneath(root,AG_TARGETS,O_PATH|O_DIRECTORY|O_CLOEXEC,containment);
    if(targets<0)fail();
    int parent=open_beneath(targets,target,O_PATH|O_DIRECTORY|O_CLOEXEC,containment|RESOLVE_NO_XDEV);
    struct stat parent_info;
    if(parent<0||fstat(parent,&parent_info)||!S_ISDIR(parent_info.st_mode)
       ||parent_info.st_uid!=AG_SUPERVISOR_UID||parent_info.st_gid!=AG_UID
       ||(parent_info.st_mode&07777)!=0710)fail();
    int tree=open_beneath(parent,"tree",O_RDONLY|O_DIRECTORY|O_CLOEXEC,containment|RESOLVE_NO_XDEV);
    struct stat info;struct statvfs filesystem;
    if(tree<0||fstat(tree,&info)||fstatvfs(tree,&filesystem)
       ||!(filesystem.f_flag&ST_RDONLY)||!S_ISDIR(info.st_mode)
       ||info.st_uid!=AG_SUPERVISOR_UID||(info.st_mode&07777)!=0555)fail();
    /* peer is 3 after the close_range; avoid descriptor replacement overlap. */
    if(peer!=AG_CHANNEL_FD||dup2(tree,AG_TARGET_FD)!=AG_TARGET_FD
       ||fcntl(AG_CHANNEL_FD,F_SETFD,0)||fcntl(AG_TARGET_FD,F_SETFD,0))fail();
    if(close_range(5,~0U,0))fail();
    /* Keep harmless fixed stdio so future target opens start at FD5. The final
     * filter permits neither read nor write on these /dev/null descriptors. */
    int harmless=open("/dev/null",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    struct stat harmless_info;
    if(harmless<0||fstat(harmless,&harmless_info)||!S_ISCHR(harmless_info.st_mode)
       ||harmless_info.st_rdev!=makedev(1,3))fail();
    for(int fd=0;fd<3;fd++)if(dup2(harmless,fd)!=fd)fail();
    if(close(harmless))fail();
    if(chdir("/"))fail();
    char *arguments[]={AG_EVALUATOR,NULL};char *environment[]={NULL};
    execve(AG_EVALUATOR,arguments,environment);
    fail();
}
