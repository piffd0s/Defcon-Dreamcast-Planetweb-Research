package org.junkyard.doom;

/**
 * One DOOM map (E1M1 / MAP01 ...). Parses the standard sub-lumps that follow the
 * map marker. Data kept in parallel primitive arrays (1.1-friendly, GC-light).
 * Coordinates/heights are DOOM map units (integers).
 */
public class Level {

    // vertexes
    public int[] vx, vy;
    // linedefs
    public int[] ldV1, ldV2, ldFlags, ldFront, ldBack;
    // sidedefs
    public int[] sdXoff, sdYoff, sdSector;
    public String[] sdUpper, sdLower, sdMid;
    // segs
    public int[] segV1, segV2, segAngle, segLine, segSide, segOff;
    // subsectors
    public int[] ssCount, ssFirst;
    // nodes
    public int[] ndX, ndY, ndDx, ndDy, ndRight, ndLeft;
    public int[][] ndBBox; // [node] -> {r.top,r.bot,r.left,r.right, l.top,l.bot,l.left,l.right}
    // sectors
    public int[] secFloor, secCeil, secLight;
    public String[] secFloorTex, secCeilTex;
    // things
    public int[] thX, thY, thAngle, thType;

    public int playerX, playerY, playerAngle;

    public static final int LF_TWOSIDED = 0x0004;

    public Level(Wad w, String mapName) {
        int m = w.find(mapName);
        if (m < 0) throw new RuntimeException("no map " + mapName);
        loadVertexes(w, w.findFrom("VERTEXES", m));
        loadSectors(w, w.findFrom("SECTORS", m));
        loadSidedefs(w, w.findFrom("SIDEDEFS", m));
        loadLinedefs(w, w.findFrom("LINEDEFS", m));
        loadSegs(w, w.findFrom("SEGS", m));
        loadSSectors(w, w.findFrom("SSECTORS", m));
        loadNodes(w, w.findFrom("NODES", m));
        loadThings(w, w.findFrom("THINGS", m));
    }

    private void loadVertexes(Wad w, int idx) {
        byte[] b = w.lump(idx); int n = b.length / 4;
        vx = new int[n]; vy = new int[n];
        for (int i = 0; i < n; i++) { vx[i] = Wad.s16(b, i*4); vy[i] = Wad.s16(b, i*4+2); }
    }

    private void loadSectors(Wad w, int idx) {
        byte[] b = w.lump(idx); int n = b.length / 26;
        secFloor = new int[n]; secCeil = new int[n]; secLight = new int[n];
        secFloorTex = new String[n]; secCeilTex = new String[n];
        for (int i = 0; i < n; i++) {
            int o = i*26;
            secFloor[i] = Wad.s16(b, o);
            secCeil[i]  = Wad.s16(b, o+2);
            secFloorTex[i] = Wad.name8(b, o+4);
            secCeilTex[i]  = Wad.name8(b, o+12);
            secLight[i] = Wad.u16(b, o+20);
        }
    }

    private void loadSidedefs(Wad w, int idx) {
        byte[] b = w.lump(idx); int n = b.length / 30;
        sdXoff = new int[n]; sdYoff = new int[n]; sdSector = new int[n];
        sdUpper = new String[n]; sdLower = new String[n]; sdMid = new String[n];
        for (int i = 0; i < n; i++) {
            int o = i*30;
            sdXoff[i] = Wad.s16(b, o);
            sdYoff[i] = Wad.s16(b, o+2);
            sdUpper[i] = Wad.name8(b, o+4);
            sdLower[i] = Wad.name8(b, o+12);
            sdMid[i]   = Wad.name8(b, o+20);
            sdSector[i] = Wad.u16(b, o+28);
        }
    }

    private void loadLinedefs(Wad w, int idx) {
        byte[] b = w.lump(idx); int n = b.length / 14;
        ldV1 = new int[n]; ldV2 = new int[n]; ldFlags = new int[n];
        ldFront = new int[n]; ldBack = new int[n];
        for (int i = 0; i < n; i++) {
            int o = i*14;
            ldV1[i] = Wad.u16(b, o);
            ldV2[i] = Wad.u16(b, o+2);
            ldFlags[i] = Wad.u16(b, o+4);
            ldFront[i] = Wad.u16(b, o+10);
            ldBack[i]  = Wad.u16(b, o+12);   // 0xFFFF = no back side
        }
    }

    private void loadSegs(Wad w, int idx) {
        byte[] b = w.lump(idx); int n = b.length / 12;
        segV1 = new int[n]; segV2 = new int[n]; segAngle = new int[n];
        segLine = new int[n]; segSide = new int[n]; segOff = new int[n];
        for (int i = 0; i < n; i++) {
            int o = i*12;
            segV1[i] = Wad.u16(b, o);
            segV2[i] = Wad.u16(b, o+2);
            segAngle[i] = Wad.s16(b, o+4);
            segLine[i] = Wad.u16(b, o+6);
            segSide[i] = Wad.u16(b, o+8);
            segOff[i] = Wad.s16(b, o+10);
        }
    }

    private void loadSSectors(Wad w, int idx) {
        byte[] b = w.lump(idx); int n = b.length / 4;
        ssCount = new int[n]; ssFirst = new int[n];
        for (int i = 0; i < n; i++) {
            ssCount[i] = Wad.u16(b, i*4);
            ssFirst[i] = Wad.u16(b, i*4+2);
        }
    }

    private void loadNodes(Wad w, int idx) {
        byte[] b = w.lump(idx); int n = b.length / 28;
        ndX = new int[n]; ndY = new int[n]; ndDx = new int[n]; ndDy = new int[n];
        ndRight = new int[n]; ndLeft = new int[n]; ndBBox = new int[n][8];
        for (int i = 0; i < n; i++) {
            int o = i*28;
            ndX[i] = Wad.s16(b, o);    ndY[i] = Wad.s16(b, o+2);
            ndDx[i] = Wad.s16(b, o+4); ndDy[i] = Wad.s16(b, o+6);
            for (int k = 0; k < 8; k++) ndBBox[i][k] = Wad.s16(b, o+8+k*2);
            ndRight[i] = Wad.u16(b, o+24);
            ndLeft[i]  = Wad.u16(b, o+26);
        }
    }

    private void loadThings(Wad w, int idx) {
        byte[] b = w.lump(idx); int n = b.length / 10;
        thX = new int[n]; thY = new int[n]; thAngle = new int[n]; thType = new int[n];
        for (int i = 0; i < n; i++) {
            int o = i*10;
            thX[i] = Wad.s16(b, o);
            thY[i] = Wad.s16(b, o+2);
            thAngle[i] = Wad.s16(b, o+4);
            thType[i] = Wad.u16(b, o+6);
            if (thType[i] == 1) {           // player 1 start
                playerX = thX[i]; playerY = thY[i]; playerAngle = thAngle[i];
            }
        }
    }

    public boolean twoSided(int line) { return (ldFlags[line] & LF_TWOSIDED) != 0; }
}
