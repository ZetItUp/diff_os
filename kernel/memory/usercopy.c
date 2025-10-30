#include <stddef.h>
#include <stdint.h>
#include "paging.h"

extern void *kmalloc(size_t n);
extern void  kfree(void *p);

static inline void outb(uint16_t port, uint8_t val){ __asm__ volatile("outb %0,%1"::"a"(val),"Nd"(port)); }
static inline uint8_t inb(uint16_t port){ uint8_t r; __asm__ volatile("inb %1,%0":"=a"(r):"Nd"(port)); return r; }

#define COM1_BASE 0x3F8

static inline void s_putc(char c){
    while((inb(COM1_BASE+5)&0x20)==0){}
    outb(COM1_BASE,(uint8_t)c);
}
static void s_puts(const char *s){
    if(!s) return;
    for(;*s;++s) s_putc(*s);
}
static void s_puthex32(uint32_t v){
    static const char hexd[16]="0123456789ABCDEF";
    s_puts("0x");
    for(int i=7;i>=0;--i){ uint8_t nyb=(uint8_t)((v>>(i*4))&0xF); s_putc(hexd[nyb]); }
}
static void s_putu(uint32_t v){
    char buf[16]; int i=0; if(v==0){ s_putc('0'); return; }
    while(v&&i<(int)sizeof(buf)){ buf[i++]=(char)('0'+(v%10)); v/=10; }
    while(i--) s_putc(buf[i]);
}

#define DBG(msg) s_puts(msg)
#define DBG_HEX(tag,val) do{ s_puts(tag); s_puthex32((uint32_t)(val)); s_puts("\r\n"); }while(0)
#define DBG_HEX2(tag,a,b) do{ s_puts(tag); s_puthex32((uint32_t)(a)); s_puts(", "); s_puthex32((uint32_t)(b)); s_puts("\r\n"); }while(0)
#define DBG_COPY(tag,dst,src,n) do{ s_puts(tag); s_puts(" dst="); s_puthex32((uint32_t)(uintptr_t)(dst)); s_puts(" src="); s_puthex32((uint32_t)(uintptr_t)(src)); s_puts(" n="); s_putu((uint32_t)(n)); s_puts("\r\n"); }while(0)

static inline size_t uc_min(size_t a,size_t b){ return a<b?a:b; }
static inline size_t page_chunk(uintptr_t addr,size_t remaining){
    uint32_t off=(uint32_t)(addr&(PAGE_SIZE_4KB-1));
    size_t room=(size_t)(PAGE_SIZE_4KB-off);
    return uc_min(remaining,room);
}
static inline int range_intersects_user(const void *p,size_t n){
    if(n==0) return 0;
    uintptr_t a=(uintptr_t)p;
    uintptr_t b=a+(n-1);
    return (a >= USER_MIN) && (b < USER_MAX) && (b >= a);
}

static int ensure_user_readable(uintptr_t va){
    uint32_t pde=0,pte=0;
    if(paging_probe_pde_pte((uint32_t)va,&pde,&pte)==0 &&
       (pde&PAGE_PRESENT) &&
       ((pde&PAGE_PS)?(pde&PAGE_USER):(pte&PAGE_PRESENT))){
        return 0;
    }
    uintptr_t pg=(uintptr_t)(va&~(uintptr_t)(PAGE_SIZE_4KB-1));
    if(paging_handle_demand_fault(pg)==0 &&
       paging_check_user_range((uint32_t)va,1)==0){
        return 0;
    }
    DBG_HEX("[usercopy] ensure_user_readable FAIL @",(uint32_t)va);
    return -1;
}

static int ensure_user_writable(uintptr_t va){
    uint32_t pde=0,pte=0;
    if(paging_probe_pde_pte((uint32_t)va,&pde,&pte)==0 &&
       (pde&PAGE_PRESENT) &&
       ((pde&PAGE_PS)?((pde&PAGE_USER)&&(pde&PAGE_RW)):((pte&PAGE_PRESENT)&&(pte&PAGE_USER)&&(pte&PAGE_RW)))){
        return 0;
    }
    uintptr_t pg=(uintptr_t)(va&~(uintptr_t)(PAGE_SIZE_4KB-1));
    if(paging_handle_demand_fault(pg)==0 &&
       paging_check_user_range_writable((uint32_t)va,1)==0){
        return 0;
    }
    if(paging_handle_cow_fault(pg)==0 &&
       paging_check_user_range_writable((uint32_t)va,1)==0){
        return 0;
    }
    DBG_HEX("[usercopy] ensure_user_writable FAIL @",(uint32_t)va);
    return -1;
}

static void k_memcpy_forward(void *dst,const void *src,size_t n){
    const uint8_t *s=(const uint8_t*)src; uint8_t *d=(uint8_t*)dst;
    for(size_t i=0;i<n;++i) d[i]=s[i];
}
static void k_memset_zero(void *dst,size_t n){
    uint8_t *d=(uint8_t*)dst; for(size_t i=0;i<n;++i) d[i]=0;
}

size_t strnlen_user(const char *us,size_t limit){
    if(!us||limit==0) return 0;
    uintptr_t p=(uintptr_t)us; size_t total=0; size_t remaining=limit;
    if(p<USER_MIN||p>=USER_MAX){ DBG_HEX("[usercopy] strnlen_user: ptr out of user range: ",(uint32_t)p); return 0; }
    while(remaining){
        if(ensure_user_readable(p)!=0){ DBG_HEX("[usercopy] strnlen_user: unreadable @",(uint32_t)p); return 0; }
        size_t chunk=page_chunk(p,remaining);
        const uint8_t *q=(const uint8_t*)p;
        for(size_t i=0;i<chunk;++i){ if(q[i]==0) return total+i; }
        total+=chunk; p+=chunk; remaining-=chunk;
    }
    return total;
}

int copy_from_user(void *dst,const void *usrc,size_t n){
    if(n==0) return 0;
    if(!dst||!usrc) return -1;
    DBG_COPY("[usercopy] copy_from_user ENTER",dst,usrc,n);
    if(!range_intersects_user(usrc,n)){
        DBG("[usercopy] copy_from_user BYPASS (no user overlap)\r\n");
        k_memcpy_forward(dst,usrc,n);
        DBG("[usercopy] copy_from_user BYPASS -> OK\r\n");
        return 0;
    }
    uintptr_t a=(uintptr_t)usrc; uintptr_t b=a+(n-1);
    if(a<USER_MIN||b>=USER_MAX){ DBG_HEX2("[usercopy] copy_from_user FAIL range a..b=",a,b); return -1; }
    uint8_t *d=(uint8_t*)dst; const uint8_t *s=(const uint8_t*)usrc; size_t remaining=n;
    DBG_HEX2("[usercopy]   iter s=",(uint32_t)(uintptr_t)s,(uint32_t)remaining);
    while(remaining){
        if(ensure_user_readable((uintptr_t)s)!=0){ DBG_HEX("[usercopy]   FAIL ensure_readable @",(uint32_t)(uintptr_t)s); return -1; }
        size_t clen=page_chunk((uintptr_t)s,remaining);
        DBG("[usercopy]   chunk "); s_puts("len="); s_putu((uint32_t)clen); s_puts("  src="); s_puthex32((uint32_t)(uintptr_t)s); s_puts(" -> dst="); s_puthex32((uint32_t)(uintptr_t)d); s_puts("\r\n");
        k_memcpy_forward(d,s,clen);
        d+=clen; s+=clen; remaining-=clen;
        if(remaining){ DBG("[usercopy]   next "); s_puts("s="); s_puthex32((uint32_t)(uintptr_t)s); s_puts(" d="); s_puthex32((uint32_t)(uintptr_t)d); s_puts(" rem="); s_putu((uint32_t)remaining); s_puts("\r\n"); }
    }
    DBG("[usercopy] copy_from_user OK, total n="); s_putu((uint32_t)n); s_puts("\r\n");
    return 0;
}

int copy_to_user(void *udst,const void *src,size_t n){
    if(n==0) return 0;
    if(!udst||!src) return -1;
    DBG_COPY("[usercopy] copy_to_user ENTER",udst,src,n);
    if(!range_intersects_user(udst,n)){
        DBG("[usercopy] copy_to_user BYPASS (no user overlap)\r\n");
        k_memcpy_forward(udst,src,n);
        DBG("[usercopy] copy_to_user BYPASS -> OK\r\n");
        return 0;
    }
    uintptr_t a=(uintptr_t)udst; uintptr_t b=a+(n-1);
    if(a<USER_MIN||b>=USER_MAX){ DBG_HEX2("[usercopy] copy_to_user FAIL range a..b=",a,b); return -1; }
    uint8_t *d=(uint8_t*)udst; const uint8_t *s=(const uint8_t*)src; size_t remaining=n;
    DBG_HEX2("[usercopy]   iter d=",(uint32_t)(uintptr_t)d,(uint32_t)remaining);
    while(remaining){
        if(ensure_user_writable((uintptr_t)d)!=0){ DBG_HEX("[usercopy]   FAIL ensure_writable @",(uint32_t)(uintptr_t)d); return -1; }
        size_t clen=page_chunk((uintptr_t)d,remaining);
        DBG("[usercopy]   chunk "); s_puts("len="); s_putu((uint32_t)clen); s_puts("  src="); s_puthex32((uint32_t)(uintptr_t)s); s_puts(" -> dst="); s_puthex32((uint32_t)(uintptr_t)d); s_puts("\r\n");
        k_memcpy_forward(d,s,clen);
        d+=clen; s+=clen; remaining-=clen;
        if(remaining){ DBG("[usercopy]   next "); s_puts("d="); s_puthex32((uint32_t)(uintptr_t)d); s_puts(" s="); s_puthex32((uint32_t)(uintptr_t)s); s_puts(" rem="); s_putu((uint32_t)remaining); s_puts("\r\n"); }
    }
    DBG("[usercopy] copy_to_user OK, total n="); s_putu((uint32_t)n); s_puts("\r\n");
    return 0;
}

int zero_user(void *u_dst,size_t n){
    if(n==0) return 0;
    if(!u_dst) return -1;
    if(!range_intersects_user(u_dst,n)){ k_memset_zero(u_dst,n); return 0; }
    uintptr_t d=(uintptr_t)u_dst;
    if(d<USER_MIN||d>=USER_MAX){ DBG_HEX2("[usercopy] zero_user: udst out of user range: ",d,(uint32_t)n); return -1; }
    size_t remaining=n;
    while(remaining){
        if(ensure_user_writable(d)!=0) return -1;
        size_t chunk=page_chunk(d,remaining);
        k_memset_zero((void*)d,chunk);
        d+=chunk; remaining-=chunk;
    }
    return 0;
}

#define UC_MAX_CSTR 4096U
#define UC_MAX_ARGC 128

char *copy_user_cstr(const char *u_str){
    if(!u_str) return NULL;
    size_t n=strnlen_user(u_str,UC_MAX_CSTR-1);
    if(n==0||n>=UC_MAX_CSTR){ DBG_HEX("[usercopy] copy_user_cstr: bad/too long string @",(uint32_t)(uintptr_t)u_str); return NULL; }
    char *k=(char*)kmalloc(n+1);
    if(!k){ DBG("[usercopy] copy_user_cstr: kmalloc failed\r\n"); return NULL; }
    if(copy_from_user(k,u_str,n)!=0){ DBG("[usercopy] copy_user_cstr: copy_from_user failed\r\n"); kfree(k); return NULL; }
    k[n]='\0';
    return k;
}

char **copy_user_argv(const char *const *u_argv,int *out_argc){
    if(!u_argv) return NULL;
    int argc=0; uintptr_t up=(uintptr_t)u_argv;
    while(argc<UC_MAX_ARGC){
        if(ensure_user_readable(up)!=0){ DBG_HEX("[usercopy] copy_user_argv: argv unreadable @",(uint32_t)up); return NULL; }
        const char *u_ptr=*(const char *const *)up;
        if(u_ptr==NULL) break;
        ++argc; up+=sizeof(const char*);
    }
    if(argc==UC_MAX_ARGC){ DBG("[usercopy] copy_user_argv: too many args\r\n"); return NULL; }
    char **kargv=(char**)kmalloc((size_t)(argc+1)*sizeof(char*));
    if(!kargv){ DBG("[usercopy] copy_user_argv: kmalloc argv failed\r\n"); return NULL; }
    for(int i=0;i<argc;++i){
        uintptr_t ent=(uintptr_t)u_argv+(size_t)i*sizeof(const char*);
        if(ensure_user_readable(ent)!=0){ DBG_HEX("[usercopy] copy_user_argv: entry unreadable @",(uint32_t)ent); kargv[i]=NULL; goto fail; }
        const char *u_s=*(const char *const *)ent;
        kargv[i]=copy_user_cstr(u_s);
        if(!kargv[i]){ DBG_HEX("[usercopy] copy_user_argv: copy_user_cstr failed for @",(uint32_t)(uintptr_t)u_s); goto fail; }
    }
    kargv[argc]=NULL;
    if(out_argc) *out_argc=argc;
    return kargv;
fail:
    for(int j=0;j<argc;++j){ if(kargv[j]) kfree(kargv[j]); }
    kfree(kargv);
    return NULL;
}

void free_kargv(char **kargv){
    if(!kargv) return;
    for(int i=0;kargv[i];++i) kfree(kargv[i]);
    kfree(kargv);
}

int copy_string_from_user(char *dst,const char *usrc,size_t dst_size){
    if(!dst||!usrc||dst_size==0) return -1;
    size_t maxlen=dst_size-1;
    size_t n=strnlen_user(usrc,maxlen);
    if(n==0||n>maxlen){ DBG_HEX2("[usercopy] copy_string_from_user: bad len or too long, len=",(uint32_t)n,(uint32_t)maxlen); return -1; }
    if(copy_from_user(dst,usrc,n)!=0){ DBG("[usercopy] copy_string_from_user: copy_from_user failed\r\n"); return -1; }
    dst[n]='\0';
    return 0;
}

