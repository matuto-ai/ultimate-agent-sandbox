/* Static fixed artifacts evaluator. Never a Participant or command runner.
 * Raw observations are provisional until held-task final ACK/actual exit,
 * Supervisor target reproof + cleanup and Hub freshness/adjudication.
 */
#define _GNU_SOURCE
#include "artifact_protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static void fail(void) { _exit(125); }

/* SHA-256 over bounded path bytes only; no cryptographic authority is derived
 * from a digest alone. Network byte order constants from FIPS 180-4. */
static uint32_t rotate(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static void path_digest(const unsigned char *p,size_t length,unsigned char out[32]) {
    static const uint32_t k[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    unsigned char block[64];size_t total=(length+9+63)&~(size_t)63;
    for(size_t offset=0;offset<total;offset+=64) {
        memset(block,0,sizeof(block));
        for(size_t i=0;i<64;i++) {
            size_t pos=offset+i;
            if(pos<length)block[i]=p[pos];else if(pos==length)block[i]=0x80;
        }
        if(offset+64==total)ag_put64(block+56,(uint64_t)length*8);
        uint32_t w[64];for(unsigned i=0;i<16;i++)w[i]=ag_u32(block+i*4);
        for(unsigned i=16;i<64;i++) {
            uint32_t x=w[i-15],y=w[i-2];
            w[i]=w[i-16]+(rotate(x,7)^rotate(x,18)^(x>>3))+w[i-7]+(rotate(y,17)^rotate(y,19)^(y>>10));
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],v=h[7];
        for(unsigned i=0;i<64;i++) {
            uint32_t t=v+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^((~e)&g))+k[i]+w[i];
            uint32_t u=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));
            v=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=v;
    }
    for(unsigned i=0;i<8;i++)ag_put32(out+i*4,h[i]);
}

/* Strict shortest UTF-8, Unicode scalar count and Unix byte constraints.
 * No normalization alias: digest is exactly these canonical encoded bytes. */
static int git_component(const unsigned char *p,size_t n) {
    return n==4&&p[0]=='.'&&(p[1]=='g'||p[1]=='G')
        &&(p[2]=='i'||p[2]=='I')&&(p[3]=='t'||p[3]=='T');
}
static int path_valid(const unsigned char *p,size_t length) {
    if(!length||length>AG_MAX_PATH_BYTES)return 0;
    size_t component=0,scalars=0,start=0,depth=1;
    for(size_t i=0;i<length;) {
        unsigned char c=p[i];
        if(c<0x20||c==0x7f||c=='\\'||c=='*'||c=='?'||c=='['||c==']')return 0;
        if(c=='/') {
            if(!component||component>AG_MAX_COMPONENT_BYTES
               ||(component==1&&p[start]=='.')||(component==2&&!memcmp(p+start,"..",2))
               ||git_component(p+start,component)||++depth>AG_MAX_DEPTH)return 0;
            component=0;start=i+1;i++;scalars++;continue;
        }
        size_t n;uint32_t cp;
        if(c<0x80){n=1;cp=c;}
        else if(c>=0xc2&&c<=0xdf){n=2;cp=c&0x1f;}
        else if(c>=0xe0&&c<=0xef){n=3;cp=c&0xf;}
        else if(c>=0xf0&&c<=0xf4){n=4;cp=c&7;}
        else return 0;
        if(i+n>length)return 0;
        for(size_t j=1;j<n;j++){if((p[i+j]&0xc0)!=0x80)return 0;cp=(cp<<6)|(p[i+j]&0x3f);}
        if((n==2&&cp<0x80)||(n==3&&cp<0x800)||(n==4&&cp<0x10000)
           ||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff)||(cp>=0x7f&&cp<0xa0))return 0;
        i+=n;component+=n;if(++scalars>AG_MAX_PATH_SCALARS)return 0;
    }
    return scalars<=AG_MAX_PATH_SCALARS&&component&&component<=AG_MAX_COMPONENT_BYTES
        &&!(component==1&&p[start]=='.')&&!(component==2&&!memcmp(p+start,"..",2))
        &&!git_component(p+start,component);
}

static void limit_valid(int resource,rlim_t bound) {
    struct rlimit value;
    if(getrlimit(resource,&value)||value.rlim_cur>bound||value.rlim_max>bound)fail();
}
static void setup(void) {
    if(getuid()!=AG_UID||geteuid()!=AG_UID||getgid()!=AG_UID||getegid()!=AG_UID)fail();
    if(prctl(PR_SET_DUMPABLE,0)||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)fail();
    /* exec resets caught signals but not ignored dispositions or masks. Verify
     * the bootstrap's default/unblocked fatal timer and its remaining budget. */
    struct sigaction action;sigset_t mask;struct itimerval timer;
    if(sigaction(SIGALRM,NULL,&action)||action.sa_handler!=SIG_DFL
       ||sigprocmask(SIG_SETMASK,NULL,&mask)||sigismember(&mask,SIGALRM)!=0
       ||getitimer(ITIMER_REAL,&timer)||timer.it_interval.tv_sec||timer.it_interval.tv_usec
       ||timer.it_value.tv_sec<0||timer.it_value.tv_sec>AG_WALL_SECONDS
       ||(!timer.it_value.tv_sec&&!timer.it_value.tv_usec))fail();
    limit_valid(RLIMIT_AS,AG_MEMORY_BYTES);limit_valid(RLIMIT_CPU,AG_CPU_SECONDS);
    limit_valid(RLIMIT_NOFILE,AG_MAX_FDS);limit_valid(RLIMIT_CORE,0);
    limit_valid(RLIMIT_FSIZE,0);limit_valid(RLIMIT_NPROC,1);
    for(int fd=0;fd<(int)AG_MAX_FDS;fd++) {
        if(fd<3) {
            struct stat harmless;
            if(fstat(fd,&harmless)||!S_ISCHR(harmless.st_mode)||harmless.st_rdev!=makedev(1,3)
               ||(fcntl(fd,F_GETFL)&O_ACCMODE)!=O_RDONLY)fail();
            continue;
        }
        if(fd==AG_CHANNEL_FD||fd==AG_TARGET_FD)continue;
        if(fcntl(fd,F_GETFD)!=-1||errno!=EBADF)fail();
    }
    int kind;socklen_t size=sizeof(kind);
    if(getsockopt(AG_CHANNEL_FD,SOL_SOCKET,SO_TYPE,&kind,&size)||kind!=SOCK_SEQPACKET)fail();
    struct stat root;struct statvfs filesystem;
    if(fstat(AG_TARGET_FD,&root)||!S_ISDIR(root.st_mode)
       ||root.st_uid!=AG_SUPERVISOR_UID||(root.st_mode&07777)!=0555
       ||fstatvfs(AG_TARGET_FD,&filesystem)||!(filesystem.f_flag&ST_RDONLY))fail();
    int abi=(int)syscall(SYS_landlock_create_ruleset,NULL,0,LANDLOCK_CREATE_RULESET_VERSION);
    if(abi<3)fail(); /* mandatory REFER + TRUNCATE; never best effort */
    struct landlock_ruleset_attr rules={.handled_access_fs=
        LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_WRITE_FILE|LANDLOCK_ACCESS_FS_READ_FILE
        |LANDLOCK_ACCESS_FS_READ_DIR|LANDLOCK_ACCESS_FS_REMOVE_DIR|LANDLOCK_ACCESS_FS_REMOVE_FILE
        |LANDLOCK_ACCESS_FS_MAKE_CHAR|LANDLOCK_ACCESS_FS_MAKE_DIR|LANDLOCK_ACCESS_FS_MAKE_REG
        |LANDLOCK_ACCESS_FS_MAKE_SOCK|LANDLOCK_ACCESS_FS_MAKE_FIFO|LANDLOCK_ACCESS_FS_MAKE_BLOCK
        |LANDLOCK_ACCESS_FS_MAKE_SYM|LANDLOCK_ACCESS_FS_REFER|LANDLOCK_ACCESS_FS_TRUNCATE};
    int ruleset=(int)syscall(SYS_landlock_create_ruleset,&rules,sizeof(rules),0);
    struct landlock_path_beneath_attr path={.allowed_access=LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR,
        .parent_fd=AG_TARGET_FD};
    if(ruleset<0||syscall(SYS_landlock_add_rule,ruleset,LANDLOCK_RULE_PATH_BENEATH,&path,0)
       ||syscall(SYS_landlock_restrict_self,ruleset,0)||close(ruleset))fail();
    /* Probe mandatory openat2 inside the actual now-restricted target. */
    struct open_how how={.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
    int probe=(int)syscall(SYS_openat2,AG_TARGET_FD,".",&how,sizeof(how));
    if(probe<0||close(probe))fail();
}

#define LOAD_NR BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr))
#define LOAD_ARG(n) BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[n]))
#define DENY BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS)
#define ALLOW BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
#define ARG_FD(nr,fd) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,nr,0,4),LOAD_ARG(0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,fd,1,0),DENY,ALLOW
#define ARG_RANGE(nr,minimum) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,nr,0,5),LOAD_ARG(0),BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,minimum,0,2),BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,AG_MAX_FDS,1,0),ALLOW,DENY
/* A constant table also permits pure ELF-data/BPF interpreter tests without
 * executing this payload or installing any native kernel policy. */
static const struct sock_filter ag_filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),DENY,
        LOAD_NR,
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_exit,0,1),ALLOW,
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_exit_group,0,1),ALLOW,
        ARG_FD(SYS_read,AG_CHANNEL_FD),LOAD_NR,
        ARG_FD(SYS_write,AG_CHANNEL_FD),LOAD_NR,
        ARG_FD(SYS_openat2,AG_TARGET_FD),LOAD_NR,
        ARG_RANGE(SYS_fstat,AG_TARGET_FD),LOAD_NR,
        ARG_RANGE(SYS_getdents64,5),LOAD_NR,
        ARG_RANGE(SYS_close,5),DENY};
static void filter(void) {
    struct sock_fprog program={.len=(unsigned short)(sizeof(ag_filter)/sizeof(ag_filter[0])),
        .filter=(struct sock_filter *)ag_filter};
    if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))fail();
    /* No rt_sigreturn: no handler is installed. Timer signals terminate. No
     * socket, recvmsg, process, exec, timer/mask, metadata-path, mutation, mmap,
     * ioctl, privilege, namespace or mount syscall can pass this allowlist. */
}
static size_t request_bytes=0,output_bytes=0;
static ssize_t packet(unsigned char *p,size_t capacity) {
    ssize_t n=(ssize_t)syscall(SYS_read,AG_CHANNEL_FD,p,capacity);
    if(n<=0||n>(ssize_t)AG_MAX_RECORD_BYTES)fail();
    request_bytes+=(size_t)n;if(request_bytes>AG_MAX_REQUEST_BYTES)fail();return n;
}
static void emit(const unsigned char *p,size_t length) {
    output_bytes+=length;if(output_bytes>AG_MAX_OUTPUT_BYTES)fail();
    if(syscall(SYS_write,AG_CHANNEL_FD,p,length)!=(long)length)fail();
}
static int unchanged(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode
        &&a->st_nlink==b->st_nlink&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid
        &&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec
        &&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec
        &&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
struct linux_dirent64_local {uint64_t ino;int64_t offset;unsigned short reclen;unsigned char type;char name[];};
static uint32_t nonempty(int fd) {
    unsigned char buffer[4096];unsigned entries=0;uint32_t found=0;
    for(;;) {
        long n=syscall(SYS_getdents64,fd,buffer,sizeof(buffer));
        if(n<0)fail();
        if(n==0)return found;
        for(size_t offset=0;offset<(size_t)n;) {
            struct linux_dirent64_local *entry=(void*)(buffer+offset);
            size_t base=offsetof(struct linux_dirent64_local,name);
            if((size_t)n-offset<base+1||entry->reclen<base+1||entry->reclen>(size_t)n-offset)fail();
            size_t capacity=entry->reclen-base,length=strnlen(entry->name,capacity);
            if(!length||length==capacity||memchr(entry->name,'/',length))fail();
            if(strcmp(entry->name,".")&&strcmp(entry->name,"..")) {
                if(++entries>AG_MAX_ENTRIES)fail();
                found=1;
            }
            offset+=entry->reclen;
        }
    }
}
int main(int argc,char **argv,char **environment) {
    (void)argv;
    if(argc!=1||environment[0]!=NULL)fail();
    setup();filter(); /* before request/target-data parsing */
    unsigned char header[AG_HEADER_BYTES+1];
    if(packet(header,sizeof(header))!=AG_HEADER_BYTES||memcmp(header,"AGQ1",4))fail();
    uint32_t count=ag_u32(header+100);
    if(!count||count>AG_MAX_ITEMS)fail();
    struct stat original,current;
    if(syscall(SYS_fstat,AG_TARGET_FD,&original)
       ||(uint64_t)original.st_dev!=ag_u64(header+84)||(uint64_t)original.st_ino!=ag_u64(header+92))fail();
    memcpy(header,"AGS1",4);emit(header,AG_HEADER_BYTES);
    unsigned char seen[AG_MAX_ITEMS][32];
    for(uint32_t index=0;index<count;index++) {
        unsigned char input[12+AG_MAX_PATH_BYTES+1];
        ssize_t n=packet(input,sizeof(input));
        if(n<13||n>12+AG_MAX_PATH_BYTES||memcmp(input,"AGP1",4)
           ||ag_u32(input+4)!=index||ag_u32(input+8)!=(uint32_t)(n-12)
           ||!path_valid(input+12,(size_t)n-12))fail();
        input[n]=0;
        unsigned char observation[AG_ITEM_BYTES]={0};memcpy(observation,"AGI1",4);
        ag_put32(observation+4,index);path_digest(input+12,(size_t)n-12,observation+8);
        for(uint32_t prior=0;prior<index;prior++)if(!memcmp(seen[prior],observation+8,32))fail();
        memcpy(seen[index],observation+8,32);
        struct open_how how={.flags=O_PATH|O_CLOEXEC|O_NOFOLLOW,
            .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
        int fd=(int)syscall(SYS_openat2,AG_TARGET_FD,input+12,&how,sizeof(how));
        if(fd<0) {
            int error=errno;
            if(error==ENOENT||error==ENOTDIR)ag_put32(observation+40,AG_TYPE_MISSING);
            else {ag_put32(observation+40,AG_TYPE_ERROR);ag_put32(observation+56,(uint32_t)error);emit(observation,sizeof(observation));fail();}
        } else {
            if(fd<5||fd>=(int)AG_MAX_FDS)fail();
            struct stat before,after;
            if(syscall(SYS_fstat,fd,&before))fail();
            if(before.st_dev!=original.st_dev||before.st_uid!=AG_SUPERVISOR_UID
               ||(before.st_mode&0222)||before.st_size<0)fail();
            if(S_ISREG(before.st_mode)) {
                if(before.st_nlink!=1||(uint64_t)before.st_size>AG_MAX_BLOB_BYTES)fail();
                ag_put32(observation+40,AG_TYPE_FILE);ag_put64(observation+44,(uint64_t)before.st_size);
            } else if(S_ISDIR(before.st_mode)) {
                /* O_PATH first avoids opening device/FIFO/socket entries. Only
                 * a separately opened O_DIRECTORY FD may be enumerated. This
                 * second open must match the still-held initial node exactly. */
                struct open_how directory_how=how;
                directory_how.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW;
                int directory=(int)syscall(SYS_openat2,AG_TARGET_FD,input+12,&directory_how,sizeof(directory_how));
                struct stat directory_before,directory_after;
                if(directory<5||directory>=(int)AG_MAX_FDS
                   ||syscall(SYS_fstat,directory,&directory_before)||!unchanged(&before,&directory_before))fail();
                ag_put32(observation+40,AG_TYPE_DIRECTORY);ag_put32(observation+52,nonempty(directory));
                if(syscall(SYS_fstat,directory,&directory_after)||!unchanged(&directory_before,&directory_after)
                   ||syscall(SYS_close,directory))fail();
            } else {ag_put32(observation+40,AG_TYPE_ERROR);ag_put32(observation+56,EOPNOTSUPP);emit(observation,sizeof(observation));fail();}
            if(syscall(SYS_fstat,fd,&after)||!unchanged(&before,&after)||syscall(SYS_close,fd))fail();
        }
        emit(observation,sizeof(observation));
    }
    if(syscall(SYS_fstat,AG_TARGET_FD,&current)||!unchanged(&original,&current))fail();
    memcpy(header,"AGF1",4);emit(header,AG_HEADER_BYTES);
    unsigned char acknowledgment[37];
    if(packet(acknowledgment,sizeof(acknowledgment))!=36||memcmp(acknowledgment,"AGA1",4)
       ||memcmp(acknowledgment+4,header+4,32))fail();
    _exit(0); /* Hub must have validated ACK while this held task was alive. */
}
