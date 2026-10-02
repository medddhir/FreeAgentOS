/* B8 fixed finite probes. Stress modes require later owned containment; DO NOT
 * launch in Stage31C. No providers, shell, project reads or arbitrary parameters.
 * --observe is the sole unprivileged/no-stress observation test mode. */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <poll.h>

static uint64_t ms(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)) _exit(125);
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static void started(const char *kind) {
    printf("{\"schema_version\":1,\"fixture\":\"FREEAGENTOS_SECURITY_V1\",\"event\":\"STARTED\",\"probe\":\"%s\"}\n",kind);
    fflush(stdout);
}
static int done(const char *kind,unsigned count) {
    printf("{\"schema_version\":1,\"fixture\":\"FREEAGENTOS_SECURITY_V1\",\"event\":\"COMPLETED\",\"probe\":\"%s\",\"work\":%u}\n",kind,count);
    return 0;
}
/* This is a local refusal guard, NOT evidence of trusted containment. The later
 * launcher must separately approve the artifact and configure the owned scope.
 * No command line or environment can request arbitrary work amounts. */
static int contained(void) {
    /* A fixed private launcher pipe, released only after independent owned-scope
     * checks. Current B7 launcher closes FD3: no stress execution path exists. */
    struct stat gate;char grant=0;
    struct pollfd ready={3,POLLIN,0};
    if(fstat(3,&gate) || !S_ISFIFO(gate.st_mode) || poll(&ready,1,1000)!=1 || !(ready.revents&POLLIN) || read(3,&grant,1)!=1 || grant!='G') return 0;
    close(3);
    FILE *f=fopen("/proc/self/status","r");char line[256];int inner=0,nnp=0;unsigned long long caps=~0ULL;
    if(!f || getuid()==0 || geteuid()==0) { if(f) fclose(f);return 0; }
    while(fgets(line,sizeof line,f)) {
        if(!strncmp(line,"NSpid:",6)) { char *p=line+6;long n=0;while(*p) {char *end;long v=strtol(p,&end,10);if(end==p) break;n=v;p=end;}inner=n==1; }
        if(!strncmp(line,"NoNewPrivs:",11)) nnp=atoi(line+11)==1;
        if(!strncmp(line,"CapEff:",7)) sscanf(line+7,"%llx",&caps);
    }
    fclose(f);return inner && nnp && caps==0;
}
static void bounded_cpu(void) {
    uint64_t end=ms()+3000;volatile uint64_t acc=1;
    for(unsigned long i=0;i<1000000000UL;++i) {
        acc=acc*1664525+1013904223;
        if((i&4095)==0 && ms()>=end) break;
    }
}
int main(int argc,char **argv) {
    if(argc!=2) return 125;
    const char *kind=NULL;
    if(!strcmp(argv[1],"--observe")) kind="observe";
    else if(!strcmp(argv[1],"--cpu")) kind="cpu";
    else if(!strcmp(argv[1],"--memory")) kind="memory";
    else if(!strcmp(argv[1],"--pids")) kind="pids";
    if(!kind) return 125;
    if(strcmp(kind,"observe") && !contained()) return 125;
    started(kind);
    if(!strcmp(kind,"observe")) return done(kind,0);
    /* Redundant fixture-local wall bound; supervisor lease is never altered. */
    alarm(5);
    if(!strcmp(kind,"cpu")) {
        pid_t children[2];unsigned n=0;
        for(unsigned i=0;i<2;++i) { pid_t p=fork();if(p<0) break;if(!p) {bounded_cpu();_exit(0);}children[n++]=p; }
        for(unsigned i=0;i<n;++i) if(waitpid(children[i],NULL,0)<0) return 125;
        return n==2?done(kind,n):125;
    }
    if(!strcmp(kind,"memory")) {
        const size_t bound=96*1024*1024;volatile unsigned char *buffer=malloc(bound);
        if(!buffer) return 125;
        uint64_t end=ms()+4000;unsigned pages=0;
        for(size_t i=0;i<bound;i+=4096) { if(ms()>=end) break;buffer[i]=(unsigned char)i;++pages; }
        free((void *)buffer);return done(kind,pages);
    }
    pid_t children[16];unsigned n=0;uint64_t end=ms()+4000;
    for(unsigned i=0;i<16 && ms()<end;++i) {
        pid_t p=fork();if(p<0) { if(errno!=EAGAIN) return 125;break; }
        if(!p) { for(unsigned j=0;j<400 && ms()<end;++j) {struct timespec t={0,10000000};nanosleep(&t,NULL);} _exit(0); }
        children[n++]=p;
    }
    for(unsigned i=0;i<n;++i) if(waitpid(children[i],NULL,0)<0) return 125;
    return done(kind,n);
}
