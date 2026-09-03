package org.junkyard.doom;

/**
 * DOOM WAD loader. PersonalJava 1.1.8 compatible (no generics/nio).
 * WAD integers are little-endian; DataInputStream is big-endian, so we read
 * straight out of the in-memory byte[] with LE helpers.
 *
 * The whole WAD is held in memory. On the 16MB Dreamcast use the ~4MB shareware
 * DOOM1.WAD; Freedoom (28MB) is for off-device development only.
 */
public class Wad {

    public final byte[] data;
    public final int numLumps;
    public final int dirOff;
    public final String[] names;
    public final int[] pos;
    public final int[] len;

    public Wad(byte[] d) {
        this.data = d;
        // header: 4-byte magic ("IWAD"/"PWAD"), int numlumps, int infotableofs
        this.numLumps = i32(d, 4);
        this.dirOff = i32(d, 8);
        names = new String[numLumps];
        pos = new int[numLumps];
        len = new int[numLumps];
        for (int i = 0; i < numLumps; i++) {
            int o = dirOff + i * 16;
            pos[i] = i32(d, o);
            len[i] = i32(d, o + 4);
            names[i] = name8(d, o + 8);
        }
    }

    /** first lump index with this name, or -1 */
    public int find(String n) {
        for (int i = 0; i < numLumps; i++) if (names[i].equals(n)) return i;
        return -1;
    }

    /** first lump index with this name at/after 'from' (for map sub-lumps) */
    public int findFrom(String n, int from) {
        for (int i = from; i < numLumps; i++) if (names[i].equals(n)) return i;
        return -1;
    }

    public byte[] lump(int idx) {
        byte[] b = new byte[len[idx]];
        System.arraycopy(data, pos[idx], b, 0, len[idx]);
        return b;
    }

    public byte[] lump(String n) {
        int i = find(n);
        return i < 0 ? null : lump(i);
    }

    // --- little-endian / name helpers (static so Level/Textures share them) ---
    public static int i32(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8)
             | ((b[o + 2] & 0xff) << 16) | ((b[o + 3] & 0xff) << 24);
    }

    public static int u16(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8);
    }

    /** signed 16-bit (vertex coords, angles, etc. are signed) */
    public static int s16(byte[] b, int o) {
        int v = u16(b, o);
        return (v >= 0x8000) ? v - 0x10000 : v;
    }

    public static String name8(byte[] b, int o) {
        int n = 0;
        while (n < 8 && b[o + n] != 0) n++;
        char[] c = new char[n];
        for (int i = 0; i < n; i++) c[i] = (char) (b[o + i] & 0xff);
        return new String(c).toUpperCase();
    }
}
