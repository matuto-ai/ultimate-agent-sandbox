/* Single-process exact-argv command profile. Never a shell or Participant.
 * The trusted parent alone owns the private Gate channel. Command code sees
 * only harmless stdin and two output pipes, an immutable executable at exec,
 * a read-only disposable target, and read-only provisioned runtime libraries.
 * No children, network, credentials, target writes or mutable checkout access.
 */
#define main artifact_unused_main
#include "artifact_evaluator.c"
#undef main
#include <poll.h>
#include <sys/wait.h>
#include <time.h>
#include <linux/sched.h>
#include <stdio.h>

#define CG_MAX_ARGV 32U
#define CG_MAX_ENV 4U
#define CG_REQUEST_BYTES 9216U
#define CG_STREAM_LIMIT (1024U*1024U)
#define CG_CAPTURE_BYTES (CG_STREAM_LIMIT+131072U)
#define CG_TAIL_BYTES 16384U
static unsigned char output[2][CG_CAPTURE_BYTES];
static size_t output_size[2];


static uint64_t milliseconds(void) {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now))fail();
    return (uint64_t)now.tv_sec*1000U+(uint64_t)now.tv_nsec/1000000U;
}
static void bounded_limit(int resource,rlim_t bound) {
    struct rlimit value={.rlim_cur=bound,.rlim_max=bound};
    if(setrlimit(resource,&value))fail();
}
static void command_identity(void) {
    if(getuid()!=AG_UID||geteuid()!=AG_UID||getgid()!=AG_UID||getegid()!=AG_UID
       ||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_SET_DUMPABLE,0))fail();
    limit_valid(RLIMIT_AS,AG_MEMORY_BYTES);limit_valid(RLIMIT_CPU,AG_CPU_SECONDS);
    limit_valid(RLIMIT_NOFILE,AG_MAX_FDS);limit_valid(RLIMIT_CORE,0);
    limit_valid(RLIMIT_FSIZE,0);limit_valid(RLIMIT_NPROC,64);
    struct stat root;struct statvfs filesystem;
    if(fstat(AG_TARGET_FD,&root)||!S_ISDIR(root.st_mode)||root.st_uid!=AG_SUPERVISOR_UID
       ||(root.st_mode&07777)!=0555||fstatvfs(AG_TARGET_FD,&filesystem)
       ||!(filesystem.f_flag&ST_RDONLY))fail();
    for(int fd=5;fd<(int)AG_MAX_FDS;fd++)if(fcntl(fd,F_GETFD)!=-1||errno!=EBADF)fail();
    for(int fd=0;fd<3;fd++) {
        struct stat node;
        if(fstat(fd,&node)||!S_ISCHR(node.st_mode)||node.st_rdev!=makedev(1,3)
           ||(fcntl(fd,F_GETFL)&O_ACCMODE)!=O_RDONLY)fail();
    }
    int kind;socklen_t size=sizeof(kind);
    if(getsockopt(AG_CHANNEL_FD,SOL_SOCKET,SO_TYPE,&kind,&size)||kind!=SOCK_SEQPACKET)fail();
    struct sigaction action;sigset_t mask;struct itimerval timer;
    if(sigaction(SIGALRM,NULL,&action)||action.sa_handler!=SIG_DFL
       ||sigprocmask(SIG_SETMASK,NULL,&mask)||sigismember(&mask,SIGALRM)!=0
       ||getitimer(ITIMER_REAL,&timer)||timer.it_interval.tv_sec||timer.it_interval.tv_usec
       ||timer.it_value.tv_sec<0||timer.it_value.tv_sec>AG_WALL_SECONDS
       ||(!timer.it_value.tv_sec&&!timer.it_value.tv_usec))fail();
}
static int immutable_directory(const char *path) {
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    struct stat node;struct statvfs filesystem;
    if(fd<0||fstat(fd,&node)||node.st_uid!=0||(node.st_mode&0022)
       ||fstatvfs(fd,&filesystem)||!(filesystem.f_flag&ST_RDONLY))fail();
    return fd;
}
static void read_rule(int ruleset,int parent,uint64_t access) {
    struct landlock_path_beneath_attr rule={.parent_fd=parent,.allowed_access=access};
    if(syscall(SYS_landlock_add_rule,ruleset,LANDLOCK_RULE_PATH_BENEATH,&rule,0))fail();
}
static void confinement(int executable,int libraries,int loader,int *dependencies,unsigned dependency_count) {
    if(syscall(SYS_landlock_create_ruleset,NULL,0,LANDLOCK_CREATE_RULESET_VERSION)<3)fail();
    struct landlock_ruleset_attr rules={.handled_access_fs=
        LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_WRITE_FILE|LANDLOCK_ACCESS_FS_READ_FILE
        |LANDLOCK_ACCESS_FS_READ_DIR|LANDLOCK_ACCESS_FS_REMOVE_DIR|LANDLOCK_ACCESS_FS_REMOVE_FILE
        |LANDLOCK_ACCESS_FS_MAKE_CHAR|LANDLOCK_ACCESS_FS_MAKE_DIR|LANDLOCK_ACCESS_FS_MAKE_REG
        |LANDLOCK_ACCESS_FS_MAKE_SOCK|LANDLOCK_ACCESS_FS_MAKE_FIFO|LANDLOCK_ACCESS_FS_MAKE_BLOCK
        |LANDLOCK_ACCESS_FS_MAKE_SYM|LANDLOCK_ACCESS_FS_REFER|LANDLOCK_ACCESS_FS_TRUNCATE};
    int ruleset=(int)syscall(SYS_landlock_create_ruleset,&rules,sizeof(rules),0);
    if(ruleset<0)fail();
    read_rule(ruleset,AG_TARGET_FD,LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR);
    read_rule(ruleset,executable,LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE);
    for(unsigned i=0;i<dependency_count;i++)read_rule(ruleset,dependencies[i],LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE);
    read_rule(ruleset,libraries,LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR);
    if(loader>=0)read_rule(ruleset,loader,LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE);
    if(syscall(SYS_landlock_restrict_self,ruleset,0)||close(ruleset))fail();
}

#define CG_ALLOW(nr) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,nr,0,1),ALLOW
/* Target code may run a dynamic language runtime, but cannot create a process,
 * network endpoint, control channel, mount, namespace or mutate a filesystem.
 * Landlock separately restricts all path reads to exact target/runtime roots.
 * execveat is only the pinned CLOEXEC FD5 initial transfer; no execve is allowed.
 */
static void child_filter(void) {
    const struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),DENY,LOAD_NR,
        CG_ALLOW(SYS_exit),CG_ALLOW(SYS_exit_group),CG_ALLOW(SYS_read),CG_ALLOW(SYS_readv),
        CG_ALLOW(SYS_pread64),CG_ALLOW(SYS_write),CG_ALLOW(SYS_writev),CG_ALLOW(SYS_close),
        CG_ALLOW(SYS_fstat),CG_ALLOW(SYS_newfstatat),CG_ALLOW(SYS_statx),CG_ALLOW(SYS_lseek),
        CG_ALLOW(SYS_openat),CG_ALLOW(SYS_openat2),CG_ALLOW(SYS_getdents64),CG_ALLOW(SYS_readlink),
        CG_ALLOW(SYS_readlinkat),CG_ALLOW(SYS_access),CG_ALLOW(SYS_faccessat),CG_ALLOW(SYS_faccessat2),
        CG_ALLOW(SYS_mmap),CG_ALLOW(SYS_mprotect),CG_ALLOW(SYS_munmap),CG_ALLOW(SYS_brk),
        CG_ALLOW(SYS_mremap),CG_ALLOW(SYS_madvise),CG_ALLOW(SYS_arch_prctl),CG_ALLOW(SYS_set_tid_address),
        CG_ALLOW(SYS_set_robust_list),CG_ALLOW(SYS_rseq),CG_ALLOW(SYS_futex),
        CG_ALLOW(SYS_rt_sigaction),CG_ALLOW(SYS_rt_sigprocmask),CG_ALLOW(SYS_rt_sigreturn),
        CG_ALLOW(SYS_sigaltstack),CG_ALLOW(SYS_getpid),CG_ALLOW(SYS_gettid),
        CG_ALLOW(SYS_getuid),CG_ALLOW(SYS_geteuid),CG_ALLOW(SYS_getgid),CG_ALLOW(SYS_getegid),
        CG_ALLOW(SYS_getgroups),CG_ALLOW(SYS_getcwd),CG_ALLOW(SYS_uname),CG_ALLOW(SYS_sysinfo),
        CG_ALLOW(SYS_getrandom),CG_ALLOW(SYS_clock_gettime),CG_ALLOW(SYS_gettimeofday),
        CG_ALLOW(SYS_clock_nanosleep),CG_ALLOW(SYS_nanosleep),CG_ALLOW(SYS_getrlimit),
        CG_ALLOW(SYS_getrusage),CG_ALLOW(SYS_sched_getaffinity),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,4),LOAD_ARG(1),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_SETPIPE_SZ,0,1),DENY,ALLOW,LOAD_NR,
        CG_ALLOW(SYS_ioctl),CG_ALLOW(SYS_poll),CG_ALLOW(SYS_ppoll),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prlimit64,0,10),
        LOAD_ARG(0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),DENY,
        LOAD_ARG(2),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),DENY,
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),DENY,ALLOW,LOAD_NR,
        CG_ALLOW(SYS_execve),CG_ALLOW(SYS_execveat),CG_ALLOW(SYS_fork),CG_ALLOW(SYS_vfork),
        CG_ALLOW(SYS_wait4),CG_ALLOW(SYS_waitid),
        /* clone3's pointer flags cannot be inspected by classic seccomp. Linux
         * runtimes may fall back to bounded legacy clone on ENOSYS. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone3,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone,0,7),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),DENY,
        LOAD_ARG(0),BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,
            ~(uint32_t)(CSIGNAL|CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD
              |CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID
              |CLONE_CHILD_SETTID|CLONE_VFORK),0,1),DENY,ALLOW,DENY};
    struct sock_fprog program={.len=(unsigned short)(sizeof(code)/sizeof(code[0])),.filter=(struct sock_filter*)code};
    if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))fail();
}

/* Installed before request parsing. Parent is a fixed deployment supervisor,
 * not target code; its extra launch/wait/signal operations are removed by the
 * second inherited child filter. Neither layer permits a network syscall. */
static void parent_filter(void) {
    const struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),DENY,LOAD_NR,
        CG_ALLOW(SYS_read),CG_ALLOW(SYS_readv),CG_ALLOW(SYS_pread64),CG_ALLOW(SYS_write),CG_ALLOW(SYS_writev),
        CG_ALLOW(SYS_close),CG_ALLOW(SYS_close_range),CG_ALLOW(SYS_openat),CG_ALLOW(SYS_openat2),
        CG_ALLOW(SYS_fstat),CG_ALLOW(SYS_newfstatat),CG_ALLOW(SYS_statx),CG_ALLOW(SYS_fstatfs),
        CG_ALLOW(SYS_getdents64),CG_ALLOW(SYS_lseek),CG_ALLOW(SYS_readlink),CG_ALLOW(SYS_readlinkat),
        CG_ALLOW(SYS_access),CG_ALLOW(SYS_faccessat),CG_ALLOW(SYS_faccessat2),CG_ALLOW(SYS_fchdir),
        CG_ALLOW(SYS_fcntl),CG_ALLOW(SYS_ioctl),CG_ALLOW(SYS_dup2),CG_ALLOW(SYS_dup3),CG_ALLOW(SYS_pipe2),
        CG_ALLOW(SYS_poll),CG_ALLOW(SYS_ppoll),CG_ALLOW(SYS_prctl),CG_ALLOW(SYS_getrlimit),
        CG_ALLOW(SYS_setrlimit),CG_ALLOW(SYS_prlimit64),CG_ALLOW(SYS_setpgid),CG_ALLOW(SYS_kill),CG_ALLOW(SYS_alarm),
        CG_ALLOW(SYS_wait4),CG_ALLOW(SYS_waitid),CG_ALLOW(SYS_fork),CG_ALLOW(SYS_vfork),
        CG_ALLOW(SYS_clone),CG_ALLOW(SYS_clone3),CG_ALLOW(SYS_execve),CG_ALLOW(SYS_execveat),
        CG_ALLOW(SYS_mmap),CG_ALLOW(SYS_mprotect),CG_ALLOW(SYS_munmap),CG_ALLOW(SYS_brk),
        CG_ALLOW(SYS_mremap),CG_ALLOW(SYS_madvise),CG_ALLOW(SYS_arch_prctl),CG_ALLOW(SYS_set_tid_address),
        CG_ALLOW(SYS_set_robust_list),CG_ALLOW(SYS_rseq),CG_ALLOW(SYS_futex),
        CG_ALLOW(SYS_rt_sigaction),CG_ALLOW(SYS_rt_sigprocmask),CG_ALLOW(SYS_rt_sigreturn),
        CG_ALLOW(SYS_sigaltstack),CG_ALLOW(SYS_getpid),CG_ALLOW(SYS_getppid),CG_ALLOW(SYS_gettid),
        CG_ALLOW(SYS_getuid),CG_ALLOW(SYS_geteuid),CG_ALLOW(SYS_getgid),CG_ALLOW(SYS_getegid),
        CG_ALLOW(SYS_getgroups),CG_ALLOW(SYS_getcwd),CG_ALLOW(SYS_uname),CG_ALLOW(SYS_sysinfo),
        CG_ALLOW(SYS_getrandom),CG_ALLOW(SYS_clock_gettime),CG_ALLOW(SYS_gettimeofday),
        CG_ALLOW(SYS_clock_nanosleep),CG_ALLOW(SYS_nanosleep),CG_ALLOW(SYS_getrusage),CG_ALLOW(SYS_sched_getaffinity),
        CG_ALLOW(SYS_landlock_create_ruleset),CG_ALLOW(SYS_landlock_add_rule),CG_ALLOW(SYS_landlock_restrict_self),
        CG_ALLOW(SYS_exit),CG_ALLOW(SYS_exit_group),DENY};
    struct sock_fprog program={.len=(unsigned short)(sizeof(code)/sizeof(code[0])),.filter=(struct sock_filter*)code};
    if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))fail();
}
static void emit_raw(const unsigned char *data,size_t length) {
    if(length>AG_MAX_RECORD_BYTES)fail();
    if(write(AG_CHANNEL_FD,data,length)!=(ssize_t)length)fail();
}
static void emit_stream(unsigned index) {
    unsigned char record[60]={0};size_t size=output_size[index],tail=size<CG_TAIL_BYTES?size:CG_TAIL_BYTES;
    memcpy(record,"CGR1",4);ag_put32(record+4,index);ag_put64(record+8,size);
    path_digest(output[index],size,record+16);ag_put32(record+48,(uint32_t)tail);ag_put32(record+52,size>CG_TAIL_BYTES);
    emit_raw(record,56);
    for(size_t offset=0;offset<tail;offset+=8192) {
        unsigned char chunk[8204];size_t amount=tail-offset;if(amount>8192)amount=8192;
        memcpy(chunk,"CGT1",4);ag_put32(chunk+4,index);ag_put32(chunk+8,(uint32_t)offset);
        memcpy(chunk+12,output[index]+size-tail+offset,amount);emit_raw(chunk,12+amount);
    }
}
static int environment_valid(const char *entry) {
    return !strcmp(entry,"LANG=C")||!strcmp(entry,"LC_ALL=C")||!strcmp(entry,"TZ=UTC")
        ||!strcmp(entry,"PYTHONDONTWRITEBYTECODE=1");
}
/* A guard death is observed by its direct parent before reaping. A parent
 * death is delivered to this fixed handler, never to project code. The guard
 * itself is the nonescaping process-group leader, so kill(0) cannot select a
 * recycled or unrelated process group. */
static void guard_stop(int signal_number) {
    (void)signal_number;
    syscall(SYS_kill,0,SIGKILL);
    _exit(125);
}
static void guard_message(int fd,uint32_t tag,uint32_t status) {
    unsigned char data[8];ag_put32(data,tag);ag_put32(data+4,status);
    if(write(fd,data,sizeof(data))!=(ssize_t)sizeof(data))fail();
}
int main(int argc,char **argv,char **environment) {
    (void)argv;
    if(argc!=1||environment[0]!=NULL)fail();command_identity();
    parent_filter();
    unsigned char request[CG_REQUEST_BYTES+1];ssize_t received=read(AG_CHANNEL_FD,request,sizeof(request));
    if(received<100||received>CG_REQUEST_BYTES||memcmp(request,"CGQ1",4))fail();
    unsigned seconds=ag_u32(request+68),arguments=ag_u32(request+72),environments=ag_u32(request+76),cwdlen=ag_u32(request+80);
    if(seconds<1||seconds>10||!arguments||arguments>CG_MAX_ARGV||environments>CG_MAX_ENV||!cwdlen||cwdlen>AG_MAX_PATH_BYTES)fail();
    unsigned process_limit=ag_u32(request+84),memory_limit=ag_u32(request+88),output_limit=ag_u32(request+92);
    if(!process_limit||process_limit>32||memory_limit<64U*1024U*1024U||memory_limit>AG_MEMORY_BYTES
       ||output_limit<1024||output_limit>CG_STREAM_LIMIT)fail();
    unsigned dependency_count=ag_u32(request+96);if(dependency_count>8)fail();
    size_t position=100;if(position+cwdlen>(size_t)received)fail();
    char cwd[AG_MAX_PATH_BYTES+1];memcpy(cwd,request+position,cwdlen);cwd[cwdlen]=0;position+=cwdlen;
    if(memchr(cwd,0,cwdlen)|| (strcmp(cwd,".")&&!path_valid((unsigned char*)cwd,cwdlen)))fail();
    char *command[CG_MAX_ARGV+1]={0},*env[CG_MAX_ENV+1]={0};char data[CG_REQUEST_BYTES];size_t used=0;
    for(unsigned index=0;index<arguments+environments;index++) {
        if(position+4>(size_t)received)fail();size_t size=ag_u32(request+position);position+=4;
        if(size>1024||position+size>(size_t)received||used+size+1>sizeof(data)||memchr(request+position,0,size))fail();
        char *value=data+used;memcpy(value,request+position,size);value[size]=0;position+=size;used+=size+1;
        if(index<arguments)command[index]=value;
        else {if(!environment_valid(value))fail();env[index-arguments]=value;}
    }
    if(strncmp(command[0],"/usr/bin/",9)||strchr(command[0]+9,'/')||!command[0][9])fail();
    const char *base=command[0]+9;
    if(!strcmp(base,"sh")||!strcmp(base,"bash")||!strcmp(base,"dash")||!strcmp(base,"zsh")
       ||!strcmp(base,"ksh")||!strcmp(base,"csh")||!strcmp(base,"tcsh")||!strcmp(base,"fish")
       ||!strcmp(base,"busybox")||!strcmp(base,"env"))fail();
    int bin=immutable_directory("/usr/bin"),libraries=immutable_directory("/usr/lib"),loader=-1;
    const char *loaders[]={"/usr/lib64/ld-linux-x86-64.so.2","/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"};
    for(unsigned i=0;i<2&&loader<0;i++) {
        loader=open(loaders[i],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(loader<0&&errno!=ENOENT&&errno!=ELOOP)fail();
    }
    if(loader>=0) {
        struct stat node;struct statvfs fs;
        if(fstat(loader,&node)||!S_ISREG(node.st_mode)||node.st_uid!=0||(node.st_mode&0022)
           ||fstatvfs(loader,&fs)||!(fs.f_flag&ST_RDONLY))fail();
    }
    struct open_how how={.flags=O_RDONLY|O_CLOEXEC|O_NOFOLLOW,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
    int executable=(int)syscall(SYS_openat2,bin,base,&how,sizeof(how));struct stat executable_before,executable_after;
    if(executable<0||fstat(executable,&executable_before)||!S_ISREG(executable_before.st_mode)
       ||executable_before.st_uid!=0||(executable_before.st_mode&0022)||!(executable_before.st_mode&0111)
       ||executable_before.st_nlink!=1||executable_before.st_size<4||executable_before.st_size>16*1024*1024)fail();
    static unsigned char executable_bytes[16*1024*1024];size_t loaded=0;
    while(loaded<(size_t)executable_before.st_size) {
        ssize_t n=read(executable,executable_bytes+loaded,(size_t)executable_before.st_size-loaded);
        if(n<=0)fail();loaded+=(size_t)n;
    }
    unsigned char digest[32];path_digest(executable_bytes,loaded,digest);
    if(memcmp(executable_bytes,"\177ELF",4)||memcmp(digest,request+36,32)
       ||fstat(executable,&executable_after)||!unchanged(&executable_before,&executable_after))fail();
    int dependencies[8];
    for(unsigned i=0;i<dependency_count;i++) {
        if(position+4>(size_t)received)fail();size_t size=ag_u32(request+position);position+=4;
        if(size<10||size>140||position+size+32>(size_t)received||memcmp(request+position,"/usr/bin/",9)
           ||memchr(request+position+9,'/',size-9)||memchr(request+position,0,size))fail();
        char path[141];memcpy(path,request+position,size);path[size]=0;position+=size;
        int fd=(int)syscall(SYS_openat2,bin,path+9,&how,sizeof(how));struct stat before,after;
        if(fd<0||fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_uid!=0||(before.st_mode&0022)
           ||!(before.st_mode&0111)||before.st_nlink!=1||before.st_size<4||before.st_size>16*1024*1024)fail();
        size_t count=0;while(count<(size_t)before.st_size) {
            ssize_t n=read(fd,executable_bytes+count,(size_t)before.st_size-count);if(n<=0)fail();count+=(size_t)n;
        }
        unsigned char actual[32];path_digest(executable_bytes,count,actual);
        if(memcmp(executable_bytes,"\177ELF",4)||memcmp(actual,request+position,32)||fstat(fd,&after)||!unchanged(&before,&after))fail();
        position+=32;dependencies[i]=fd;
    }
    if(position!=(size_t)received)fail();
    how.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC;
    int directory=(int)syscall(SYS_openat2,AG_TARGET_FD,cwd,&how,sizeof(how));if(directory<0)fail();
    confinement(executable,libraries,loader,dependencies,dependency_count);
    unsigned char header[36];memcpy(header,"CGS1",4);memcpy(header+4,request+4,32);emit_raw(header,sizeof(header));
    /* Guard is group leader. Observer pins it with WNOWAIT and is a
     * subreaper, so unexpected guard loss can never strand adopted children.
     * Observer owns output capture; guard receives no private Gate channel. */
    int pipes[2][2],metadata[2];
    if(pipe2(pipes[0],O_CLOEXEC)||pipe2(pipes[1],O_CLOEXEC)||pipe2(metadata,O_CLOEXEC)
       ||prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0))fail();
    uint64_t start=milliseconds(),deadline=start+(uint64_t)seconds*1000;
    pid_t guard=fork();if(guard<0)fail();
    if(guard==0) {
        if(setpgid(0,0)||close(AG_CHANNEL_FD)||close(metadata[0])
           ||close(pipes[0][0])||close(pipes[1][0])||prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0))fail();
        struct sigaction action={.sa_handler=guard_stop};
        if(sigemptyset(&action.sa_mask)||sigaction(SIGUSR1,&action,NULL)||sigaction(SIGALRM,&action,NULL)
           ||prctl(PR_SET_PDEATHSIG,SIGUSR1)||getppid()==1)guard_stop(SIGUSR1);
        alarm(seconds+1);
        pid_t child=fork();if(child<0)fail();
        if(child==0) {
            if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()==1||dup2(pipes[0][1],1)!=1
               ||dup2(pipes[1][1],2)!=2||fchdir(directory))fail();
            int pinned=fcntl(executable,F_DUPFD_CLOEXEC,32);if(pinned<0)fail();
            if(dup3(pinned,5,O_CLOEXEC)!=5||close_range(3,4,0)||close_range(6,~0U,0))fail();
            bounded_limit(RLIMIT_NPROC,process_limit);bounded_limit(RLIMIT_AS,memory_limit);
            bounded_limit(RLIMIT_CPU,seconds<5?seconds:5);
            child_filter();syscall(SYS_execveat,5,"",command,env,AT_EMPTY_PATH);fail();
        }
        if(close(pipes[0][1])||close(pipes[1][1]))fail();
        int root_seen=0;
        for(;;) {
            int status;pid_t done=waitpid(-1,&status,0);
            if(done>0) {
                if(done==child) {root_seen=1;guard_message(metadata[1],1,(uint32_t)status);}
                continue;
            }
            if(errno==EINTR)continue;
            if(errno!=ECHILD||!root_seen)fail();
            guard_message(metadata[1],2,0);_exit(0);
        }
    }
    if(setpgid(guard,guard)&&errno!=EACCES)fail();
    if(close(metadata[1])||close(pipes[0][1])||close(pipes[1][1]))fail();
    for(unsigned index=0;index<2;index++)if(fcntl(pipes[index][0],F_SETFL,O_NONBLOCK))fail();
    if(fcntl(metadata[0],F_SETFL,O_NONBLOCK))fail();
    int status=0,root_seen=0,tree_message=0,reaped=0,closed[2]={0},timed_out=0,limited=0,killed=0,guard_error=0;
    unsigned char meta[16];size_t meta_size=0;
    while(!reaped||!closed[0]||!closed[1]) {
        uint64_t now=milliseconds();
        siginfo_t info;memset(&info,0,sizeof(info));
        if(!killed&&waitid(P_PID,(id_t)guard,&info,WEXITED|WNOHANG|WNOWAIT))fail();
        int guard_done=info.si_pid==guard;
        for(;;) {
            unsigned char record[16];ssize_t n=read(metadata[0],record,sizeof(record));
            if(n<0) {if(errno==EAGAIN||errno==EINTR)break;fail();}
            if(n==0)break;
            if(meta_size+(size_t)n>sizeof(meta))fail();
            memcpy(meta+meta_size,record,(size_t)n);meta_size+=(size_t)n;
        }
        if(meta_size>=8) {
            if(ag_u32(meta)!=1)fail();status=(int)ag_u32(meta+4);root_seen=1;
        }
        if(meta_size==16) {
            if(ag_u32(meta+8)!=2||ag_u32(meta+12))fail();tree_message=1;
        }
        if(!killed&&(now>=deadline||limited||guard_done)) {
            timed_out=now>=deadline;limited=limited!=0;
            guard_error=guard_done&&(!tree_message||info.si_code!=CLD_EXITED||info.si_status!=0);
            /* Exactly once, before guard is reaped: never a guessed or reused
             * group. Includes guard plus all nonescaping project descendants. */
            if(kill(-guard,SIGKILL)&&errno!=ESRCH)fail();killed=1;
        }
        if(killed&&!reaped) {
            for(;;) {
                int observed;pid_t done=waitpid(-1,&observed,WNOHANG);
                if(done>0)continue;
                if(done==0)break;
                if(errno==ECHILD) {reaped=1;break;}
                if(errno!=EINTR)fail();
            }
        }
        if(now>start+12000)fail();
        struct pollfd descriptors[2];
        for(unsigned index=0;index<2;index++)descriptors[index]=(struct pollfd){.fd=closed[index]?-1:pipes[index][0],.events=POLLIN|POLLHUP};
        if(poll(descriptors,2,10)<0&&errno!=EINTR)fail();
        for(unsigned index=0;index<2;index++) {
            if(closed[index])continue;
            for(;;) {
                unsigned char block[4096];ssize_t size=read(pipes[index][0],block,sizeof(block));
                if(size<0) {if(errno==EAGAIN||errno==EINTR)break;fail();}
                if(size==0) {closed[index]=1;if(close(pipes[index][0]))fail();break;}
                if(output_size[index]+(size_t)size>CG_CAPTURE_BYTES)fail();
                memcpy(output[index]+output_size[index],block,(size_t)size);output_size[index]+=(size_t)size;
                if(output_size[index]>output_limit) {limited=1;break;}
            }
        }
    }
    if(guard_error&&!timed_out&&!limited)fail();
    if(!root_seen) {if(!timed_out&&!limited)fail();status=SIGKILL;}
    if(!WIFEXITED(status)&&!WIFSIGNALED(status))fail();
    emit_stream(0);emit_stream(1);
    unsigned char terminal[68]={0};memcpy(terminal,"CGE1",4);
    ag_put32(terminal+4,WIFEXITED(status)?(uint32_t)WEXITSTATUS(status):UINT32_MAX);
    ag_put32(terminal+8,WIFSIGNALED(status)?(uint32_t)WTERMSIG(status):0);
    ag_put32(terminal+12,timed_out);ag_put32(terminal+16,limited);ag_put64(terminal+20,milliseconds()-start);
    memcpy(terminal+28,digest,32);ag_put32(terminal+60,1);ag_put32(terminal+64,!tree_message);
    emit_raw(terminal,sizeof(terminal));
    memcpy(header,"CGF1",4);emit_raw(header,sizeof(header));
    unsigned char ack[37];
    if(read(AG_CHANNEL_FD,ack,sizeof(ack))!=36||memcmp(ack,"CGA1",4)||memcmp(ack+4,request+4,32))fail();
    _exit(0);
}
