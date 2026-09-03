package org.junkyard.doom;

import java.util.Hashtable;

/**
 * DOOM texture/flat/palette/colormap subsystem (PersonalJava 1.1 compatible).
 *
 *  - PLAYPAL  -> 256 ARGB
 *  - COLORMAP -> 34 light maps (index remap) for distance/sector lighting
 *  - flats    -> 64x64 raw palette indices
 *  - textures -> composited from patches (DOOM "picture"/column format) per
 *                PNAMES + TEXTURE1/2; stored column-major (pix[col*h + row]).
 */
public class Textures {

    public final Wad wad;
    public final int[] pal = new int[256];          // ARGB
    public final byte[][] colormap = new byte[34][];// [lightmap][palidx] -> palidx

    private final String[] pnames;
    private final Hashtable texDefs = new Hashtable();   // name -> int[] (lump,offset packed) via TexDef
    private final Hashtable texCache = new Hashtable();   // name -> Tex
    private final Hashtable flatCache = new Hashtable();  // name -> byte[4096]

    public static class Tex { public int w, h; public byte[] pix; } // column-major

    public Textures(Wad w) {
        this.wad = w;
        byte[] p = w.lump("PLAYPAL");
        for (int i = 0; i < 256; i++)
            pal[i] = 0xff000000 | ((p[i*3]&0xff)<<16) | ((p[i*3+1]&0xff)<<8) | (p[i*3+2]&0xff);
        byte[] cm = w.lump("COLORMAP");
        for (int m = 0; m < 34; m++) { colormap[m] = new byte[256]; System.arraycopy(cm, m*256, colormap[m], 0, 256); }
        pnames = loadPnames(w);
        loadTexDefs(w, "TEXTURE1");
        loadTexDefs(w, "TEXTURE2");
    }

    static String[] loadPnames(Wad w) {
        byte[] b = w.lump("PNAMES");
        int n = Wad.i32(b, 0);
        String[] s = new String[n];
        for (int i = 0; i < n; i++) s[i] = Wad.name8(b, 4 + i*8);
        return s;
    }

    // store TEXTUREx lump bytes + per-name offset so we can composite lazily
    static class TexDef { byte[] lump; int off; }
    void loadTexDefs(Wad w, String lumpName) {
        int li = w.find(lumpName);
        if (li < 0) return;
        byte[] b = w.lump(li);
        int n = Wad.i32(b, 0);
        for (int i = 0; i < n; i++) {
            int off = Wad.i32(b, 4 + i*4);
            String nm = Wad.name8(b, off);
            TexDef d = new TexDef(); d.lump = b; d.off = off;
            if (!texDefs.containsKey(nm)) texDefs.put(nm, d);
        }
    }

    public boolean isMissing(String name) {
        return name == null || name.length() == 0 || name.equals("-");
    }

    public Tex getTexture(String name) {
        if (isMissing(name)) return null;
        Object c = texCache.get(name);
        if (c != null) return (Tex) c;
        Object d = texDefs.get(name);
        if (d == null) return null;
        Tex t = composite((TexDef) d);
        texCache.put(name, t);
        return t;
    }

    Tex composite(TexDef d) {
        byte[] b = d.lump; int o = d.off;
        int w = Wad.u16(b, o + 12), h = Wad.u16(b, o + 14);
        int patchCount = Wad.u16(b, o + 20);
        Tex t = new Tex(); t.w = w; t.h = h; t.pix = new byte[w * h];
        for (int pc = 0; pc < patchCount; pc++) {
            int po = o + 22 + pc * 10;
            int ox = Wad.s16(b, po), oy = Wad.s16(b, po + 2);
            int pi = Wad.u16(b, po + 4);
            if (pi >= pnames.length) continue;
            int lump = wad.find(pnames[pi]);
            if (lump < 0) continue;
            drawPatch(t, wad.lump(lump), ox, oy);
        }
        return t;
    }

    // decode a DOOM picture (column/post format) into the composite column-major buffer
    void drawPatch(Tex t, byte[] p, int ox, int oy) {
        int pw = Wad.u16(p, 0), ph = Wad.u16(p, 2);
        for (int col = 0; col < pw; col++) {
            int dx = ox + col;
            if (dx < 0 || dx >= t.w) continue;
            int colofs = Wad.i32(p, 8 + col * 4);
            int q = colofs;
            while ((p[q] & 0xff) != 0xff) {
                int top = p[q] & 0xff;
                int len = p[q + 1] & 0xff;
                q += 3;                       // skip topdelta,len,unused
                for (int k = 0; k < len; k++) {
                    int dy = oy + top + k;
                    if (dy >= 0 && dy < t.h) t.pix[dx * t.h + dy] = p[q + k];
                }
                q += len + 1;                 // skip pixels + trailing unused
            }
        }
    }

    public byte[] getFlat(String name) {
        if (isMissing(name) || name.equals("F_SKY1")) return null;
        Object c = flatCache.get(name);
        if (c != null) return (byte[]) c;
        byte[] b = wad.lump(name);
        if (b == null || b.length < 4096) return null;
        flatCache.put(name, b);
        return b;
    }

    /** light: 0..255 sector light; depth scales darkening. returns 0..31 colormap */
    public byte[] lightMap(int light, double depth) {
        int l = light >> 3;                  // 0..31 from light
        int d = (int) (depth * 0.0040);      // distance darkening
        int idx = 31 - l + d;
        if (idx < 0) idx = 0; if (idx > 31) idx = 31;
        return colormap[idx];
    }
}
