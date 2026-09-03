/* loader.c -- native SH-4 loader stub for in-memory DOOM.
 * Runs after the exploit's return-address hijack gives native PC. It:
 *   1. scans RAM for the doom.bin header signature (crt0) inside the Java byte[]
 *      that the Eden service downloaded (no-ASLR -> deterministic, but we scan so
 *      we don't need to know the exact byte[] address);
 *   2. reads the [doomsz][wadsz] header placed just before doom.bin;
 *   3. relocates doom.bin -> DOOM_DST (0x8CC00000) and the WAD -> WAD_DST;
 *   4. patches doom's g_wad_addr/g_wad_size (fixed addrs in the relocated image);
 *   5. jumps to doom _start.
 * Built with gcc-sh-elf, linked at the staging address (0x8C29AE00); the exploit
 * payload places these bytes there and the unlink return-hijack jumps here. */
#include <stdint.h>

/* layout (matches dc_syscalls.c _sbrk + boot_doom.py; full 4MB doom1.wad):
 *   WAD   0x8C010000-0x8C410774 (4.1MB)   heap/zone 0x8C420000-0x8CC00000 (8.2MB)
 *   doom.bin 0x8CC00000        stack top 0x8CFFFFF0
 * copy() is forward; both copies have dest<src or no overlap -> safe. */
#define DOOM_DST   0x8CC00000u          /* doom.bin link base (in free region) */
#define WAD_DST    0x8C010000u          /* full 4MB WAD lands low (below the scan range) */
#define G_WAD_ADDR 0x8CC56E44u          /* doom.bin: volatile g_wad_addr (.data, after reloc) */
#define G_WAD_SIZE 0x8CC56E40u
#define SCAN_LO    0x8C420000u          /* search the Java staging byte[] above the WAD dest */
#define SCAN_HI    0x8D000000u

/* doom.bin crt0 first 8 bytes (from od of doom.bin): 06 df 07 d0 07 d1 00 e2 */
static const uint8_t SIG[8] = {0x06,0xdf,0x07,0xd0,0x07,0xd1,0x00,0xe2};

static void copy(uint8_t* d, const uint8_t* s, uint32_t n){ while(n--) *d++ = *s++; }

__attribute__((section(".text.start"))) void loader(void)
{
    const uint8_t* p = (const uint8_t*)SCAN_LO;
    const uint8_t* found = 0;
    for (; p < (const uint8_t*)SCAN_HI; p += 4) {
        if (p[0]==SIG[0] && p[1]==SIG[1] && p[2]==SIG[2] && p[3]==SIG[3] &&
            p[4]==SIG[4] && p[5]==SIG[5] && p[6]==SIG[6] && p[7]==SIG[7]) {
            found = p; break;
        }
    }
    if (!found) return;                          /* byte[] not located */

    /* header [doomsz][wadsz] sits 8 bytes before the signature */
    uint32_t doomsz = *(const uint32_t*)(found - 8);
    uint32_t wadsz  = *(const uint32_t*)(found - 4);

    copy((uint8_t*)WAD_DST,  found + doomsz, wadsz);   /* WAD first (doom src still intact) */
    copy((uint8_t*)DOOM_DST, found, doomsz);           /* relocate the engine */

    *(volatile uint32_t*)G_WAD_ADDR = WAD_DST;         /* tell doom where the WAD is */
    *(volatile uint32_t*)G_WAD_SIZE = wadsz;

    ((void(*)(void))DOOM_DST)();                       /* jump to doom _start */
}
