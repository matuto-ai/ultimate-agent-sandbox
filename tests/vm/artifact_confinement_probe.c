/* Deliberate disposable-VM attack payload, never production evaluator.
 * Same actual setup/filter functions compiled from the evaluator source;
 * distinct binary/profile hashes and fixed test bootstrap. No project commands.
 */
#define main artifact_unused_main
#include "../../runtime/workstation/artifact_evaluator.c"
#undef main
int main(int argc,char **argv,char **environment) {
    (void)argv;
    if(argc!=1||environment[0]!=NULL)fail();
    setup();filter();
    unsigned char test[2];
    if(packet(test,sizeof(test))!=1)fail();
    struct open_how how={.flags=O_RDONLY|O_CLOEXEC,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
    long result;
    switch(test[0]) {
    case 'N': syscall(SYS_socket,AF_INET,SOCK_STREAM,0);break;
    case 'P': syscall(SYS_clone,0,0,0,0,0);break;
    case 'F': syscall(SYS_read,0,test,sizeof(test));break;
    case 'E': syscall(SYS_execve,"/bin/true",NULL,NULL);break;
    case 'T': syscall(SYS_alarm,0);break;
    case 'M': syscall(SYS_mmap,NULL,AG_MEMORY_BYTES+1,3,0x22,-1,0);break;
    case 'C': for(volatile unsigned long count=0;;count++){};
    case 'H': syscall(SYS_read,AG_CHANNEL_FD,test,1);break;
    case 'R':
        result=syscall(SYS_openat2,AG_TARGET_FD,"../store/config",&how,sizeof(how));
        if(result<0&&errno==EXDEV)_exit(0);
        break;
    case 'L':
        how.resolve=0; /* Deliberately bypass resolution in this TEST only. */
        result=syscall(SYS_openat2,AG_TARGET_FD,"/opt/uas/bin/artifact-evaluator",&how,sizeof(how));
        if(result<0&&errno==EACCES)_exit(0); /* Actual Landlock outside denial. */
        break;
    case 'W':
        how.flags=O_WRONLY|O_CLOEXEC;
        result=syscall(SYS_openat2,AG_TARGET_FD,"README.md",&how,sizeof(how));
        if(result<0&&(errno==EACCES||errno==EROFS))_exit(0);
        break;
    case 'O': {
        unsigned char excessive[16385];memset(excessive,'x',sizeof(excessive));
        /* Deliberately outside the bounded emitter, for receiver failure proof. */
        syscall(SYS_write,AG_CHANNEL_FD,excessive,sizeof(excessive));
        syscall(SYS_read,AG_CHANNEL_FD,test,1);break;
    }
    default:fail();
    }
    _exit(126); /* Every unexpected return/non-denial is a failed native proof. */
}
