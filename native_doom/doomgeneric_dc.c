/* doomgeneric_dc.c -- bare-metal Dreamcast platform layer for doomgeneric,
 * designed to run as INJECTED code inside the exploited PlanetWeb browser (no
 * KOS). It REUSES the browser's already-initialised video output: the PVR scans
 * out VRAM continuously regardless of which code owns the SH-4, so DOOM just
 * writes the existing framebuffer.
 *
 * Live-read PVR display regs (browser's mode):
 *   FB_R_CTRL 0xA05F8044 = 1        -> RGB555, enabled
 *   FB_R_SOF1 0xA05F8050 = 0x600000 -> framebuffer @ VRAM 0xA5600000
 *   FB_R_SIZE 0xA05F805C            -> 640 px wide
 * DOOM renders 320x200 ARGB into DG_ScreenBuffer; we 2x-scale -> 640x400 (RGB555),
 * vertically centred on the 640x480 screen.
 *
 * Timer: SH-4 TMU channel 2 (likely free; browser uses TMU0/1), Pck/64.
 * Input: TODO (poll the browser's Maple controller buffer or Maple DMA) -- the
 *   first build runs DOOM's attract/demo loop, which already proves DOOM-on-screen.
 */
#include "doomgeneric.h"
#include "doomkeys.h"
#include <stdint.h>
#include <stdio.h>

/* ---- Dreamcast hardware ---- */
/* PVR display registers (P2, uncached) -- LIVE-READ so we target the browser's ACTUAL
 * current framebuffer (its VRAM address/size can differ per boot; hardcoding 0xA5600000
 * made DOOM render to an off-screen buffer -> the frozen browser was still displayed). */
#define FB_R_CTRL (*(volatile uint32_t*)0xA05F8044u)
#define FB_R_SOF1 (*(volatile uint32_t*)0xA05F8050u)
#define FB_R_SIZE (*(volatile uint32_t*)0xA05F805Cu)
#define VRAM64_BASE 0xA5000000u

static volatile uint16_t* g_fb = (volatile uint16_t*)0xA5600000u;  /* display fb (live) */
static int FB_W = 640;     /* pixels per scanline (from FB_R_SIZE) */
static int FB_H = 480;     /* scanlines */
static int DY   = 40;      /* vertical centering of the 400px image */
static int g_565 = 0;      /* 0 = RGB555, 1 = RGB565 */

/* SH-4 TMU (P4) */
#define TSTR  (*(volatile uint8_t *)0xFFD80004u)
#define TCOR2 (*(volatile uint32_t*)0xFFD80020u)
#define TCNT2 (*(volatile uint32_t*)0xFFD80024u)
#define TCR2  (*(volatile uint16_t*)0xFFD80028u)
#define PCK_DIV64_PER_MS  781u   /* ~50MHz/64/1000 */

void DG_Init(void)
{
    /* video is already up (browser): LIVE-READ where the PVR is actually scanning out,
     * so DOOM draws into the on-screen framebuffer regardless of this boot's layout. */
    uint32_t ctrl = FB_R_CTRL, sof1 = FB_R_SOF1, size = FB_R_SIZE;
    if (ctrl & 1) {                                 /* display enabled */
        g_fb  = (volatile uint16_t*)(VRAM64_BASE + (sof1 & 0x00FFFFFFu));
        g_565 = ((ctrl >> 2) & 3) == 1;             /* fb_depth: 0=RGB555, 1=RGB565 */
        int words_per_line = (int)(size & 0x3FF) + 1;   /* 32-bit words per scanline */
        int lines          = (int)((size >> 10) & 0x3FF) + 1;
        FB_W = words_per_line * 2;                   /* 2 px per 32-bit word (16bpp) */
        FB_H = lines;
        if (FB_W < 320 || FB_W > 1024) FB_W = 640;   /* sanity fallbacks */
        if (FB_H < 200 || FB_H > 600) FB_H = 480;
        DY = (FB_H - DOOMGENERIC_RESY*2) / 2;
        if (DY < 0) DY = 0;
    }
    /* set up TMU2 as a free-running down counter */
    TSTR  &= ~0x04;            /* stop ch2 */
    TCOR2  = 0xFFFFFFFFu;
    TCNT2  = 0xFFFFFFFFu;
    TCR2   = 0x0002;           /* Pck/64 */
    TSTR  |= 0x04;             /* start ch2 */
}

uint32_t DG_GetTicksMs(void)
{
    return (0xFFFFFFFFu - TCNT2) / PCK_DIV64_PER_MS;
}

void DG_SleepMs(uint32_t ms)
{
    uint32_t t = DG_GetTicksMs();
    while ((DG_GetTicksMs() - t) < ms) { /* spin */ }
}

void DG_DrawFrame(void)
{
    uint32_t* src = DG_ScreenBuffer;          /* RESX*RESY ARGB8888 */
    for (int y = 0; y < DOOMGENERIC_RESY; y++) {
        volatile uint16_t* row = &g_fb[(DY + y*2)*FB_W];
        for (int x = 0; x < DOOMGENERIC_RESX; x++) {
            uint32_t p = src[y*DOOMGENERIC_RESX + x];
            uint16_t px;
            if (g_565)
                px = (uint16_t)(((p >> 8) & 0xF800) |    /* R5 */
                                ((p >> 5) & 0x07E0) |    /* G6 */
                                ((p >> 3) & 0x001F));    /* B5 */
            else
                px = (uint16_t)(((p >> 9) & 0x7C00) |    /* R5 */
                                ((p >> 6) & 0x03E0) |    /* G5 */
                                ((p >> 3) & 0x001F));    /* B5 */
            int dx = x*2;
            row[dx] = px; row[dx+1] = px;
            row[FB_W+dx] = px; row[FB_W+dx+1] = px;          /* 2x2 block */
        }
    }
}

int DG_GetKey(int* pressed, unsigned char* key)
{
    (void)pressed; (void)key;
    return 0;   /* TODO: Maple controller -> DOOM keys */
}

void DG_SetWindowTitle(const char* title) { (void)title; }

int main(int argc, char** argv)
{
    static char a0[]="doom", a1[]="-iwad", a2[]="doom.wad";
    static char* av[]={a0,a1,a2};
    setvbuf(stdout, NULL, _IONBF, 0);   /* unbuffered: flush each printf to the debug log immediately */
    doomgeneric_Create(3, av);
    for (;;)
        doomgeneric_Tick();
    return 0;
}
