/* dc_syscalls.c -- newlib glue for bare-metal Dreamcast DOOM (no OS).
 * malloc -> bump heap in free RAM; file I/O -> single in-memory WAD buffer.
 * The loader stages the WAD into RAM and fills g_wad_addr/g_wad_size. */
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#undef errno
extern int errno;

/* --- heap for malloc (free no-ASLR RAM region; sized at integration) --- */
void* _sbrk(int incr){
    static char* hp=(char*)0x8C790000;  /* heap above trimmed WAD (0x8C450000..~0x8C78D67C); ~4.6MB to DOOM img */
    char* p=hp;
    if(hp+incr>(char*)0x8CC00000){ errno=ENOMEM; return (void*)-1; }
    hp+=incr; return p;
}

/* --- in-memory WAD (filled by the loader) --- */
volatile uint32_t g_wad_addr = 0xFFFFFFFF; /* .data: survives crt0 bss-clear */        /* RAM addr of the WAD bytes */
volatile uint32_t g_wad_size = 0xFFFFFFFF;
static long wad_pos = 0;
static int  wad_open = 0;

int _open(const char* path,int flags,int mode){ (void)path;(void)flags;(void)mode;
    wad_pos=0; wad_open=1; return 3; }       /* every open -> the WAD, fd 3 */
int _close(int fd){ if(fd==3) wad_open=0; return 0; }
int _read(int fd,char* buf,int len){
    if(fd!=3||!wad_open) return 0;
    long rem=(long)g_wad_size-wad_pos; if(len>rem) len=rem; if(len<0) len=0;
    const char* w=(const char*)g_wad_addr;
    for(int i=0;i<len;i++) buf[i]=w[wad_pos+i];
    wad_pos+=len; return len;
}
int _lseek(int fd,int off,int whence){
    if(fd!=3) return 0;
    if(whence==0) wad_pos=off; else if(whence==1) wad_pos+=off; else wad_pos=(long)g_wad_size+off;
    return wad_pos;
}
static int dbgpos=0;
int _write(int fd,const char* buf,int len){ (void)fd;
    volatile char* d=(volatile char*)0x8CF00000;   /* debug log (above DOOM img 0x8CE80000, below stack; OUT of heap) */
    for(int i=0;i<len && dbgpos<0x8000;i++) d[dbgpos++]=buf[i];
    return len; }
int _fstat(int fd,struct stat* st){ (void)fd; st->st_mode=S_IFREG; st->st_size=g_wad_size; return 0; }
int _isatty(int fd){ (void)fd; return 1; }
int _kill(int pid,int sig){ (void)pid;(void)sig; errno=EINVAL; return -1; }
int _getpid(void){ return 1; }
void _exit(int code){ (void)code; for(;;){} }

/* extra newlib stubs */
int _mkdir(const char* p,int m){ (void)p;(void)m; return -1; }
int _stat(const char* p,struct stat* st){ (void)p; if(st) st->st_mode=S_IFCHR; return 0; }
int _link(const char* a,const char* b){ (void)a;(void)b; return -1; }
int _unlink(const char* p){ (void)p; return -1; }
int _gettimeofday(void* tv,void* tz){ (void)tv;(void)tz; return 0; }
int _times(void* b){ (void)b; return -1; }
char* getenv(const char* n){ (void)n; return 0; }
char** environ = 0;
int mkdir(const char* p, mode_t m){ (void)p;(void)m; return -1; }
