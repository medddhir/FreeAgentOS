/* Fixed Stage31D fixture: no provider, project, network or shell. */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/prctl.h>
static unsigned long long cap(const char *key) {
    FILE *f=fopen("/proc/self/status","r"); char line[256]; unsigned long long v=~0ULL;
    if (!f) return v;
    while (fgets(line,sizeof line,f)) if (!strncmp(line,key,strlen(key))) sscanf(line+strlen(key),"%llx",&v);
    fclose(f); return v;
}
int main(int argc,char **argv) {
    if(argc!=2 || strcmp(argv[1],"--synthetic")) return 125;
    struct stat p,m; int ns=stat("/proc/self/ns/pid",&p)==0 && stat("/proc/self/ns/mnt",&m)==0;
    printf("{\"schema_version\":1,\"uid\":%u,\"gid\":%u,\"pid\":%u,\"pid_ns\":%llu,\"mount_ns\":%llu,\"capabilities_clear\":%s,\"no_new_privs\":%s,\"host_root_visible\":%s}\n",
           (unsigned)getuid(),(unsigned)getgid(),(unsigned)getpid(),ns?(unsigned long long)p.st_ino:0,
           ns?(unsigned long long)m.st_ino:0,
           cap("CapEff:")==0 && cap("CapPrm:")==0 && cap("CapInh:")==0 && cap("CapAmb:")==0 && cap("CapBnd:")==0?"true":"false",
           prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1?"true":"false",access("/root",F_OK)==0?"true":"false");
    fflush(stdout);
    if(fork()==0) { for(;;) sleep(300); }
    for(;;) sleep(300);
}
