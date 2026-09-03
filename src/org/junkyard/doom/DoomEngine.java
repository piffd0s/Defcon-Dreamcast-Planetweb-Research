package org.junkyard.doom;

/**
 * Real DOOM BSP renderer (PersonalJava 1.1 / pure int+double math, no AWT).
 * Front-to-back BSP traversal, perspective-correct textured walls, portal
 * windows with per-column occlusion clip arrays, COLORMAP lighting, and
 * VISPLANE (R_MakeSpans) floor/ceiling rendering -- one depth+lightmap per
 * horizontal scanline, world coords marched per pixel (no per-pixel divide).
 * Writes ARGB to an int[] framebuffer (headless-testable; AWT shell blits it).
 */
public class DoomEngine {

    public final Wad wad;
    public final Level lv;
    public final Textures tex;

    public double viewX, viewY, viewZ, viewAngle;
    int W, H, cx, cy;
    double proj;
    int[] fb;
    int[] upper, lower;
    double cosA, sinA;
    static final double EYE = 41.0;
    static final double NEAR = 1.0;
    static final int PEGTOP = 0x8, PEGBOT = 0x10;
    static final int SKY = 0xff6080a0;

    // visplane pool
    static final int MAXPLANES = 512;
    Plane[] planes = new Plane[MAXPLANES];
    int planeCount;
    java.util.Hashtable planeMap = new java.util.Hashtable();
    int[] spanstart;

    static class Plane {
        byte[] flat; int height, light, minx, maxx;
        int[] top, bottom;
        Plane(int w) { top = new int[w]; bottom = new int[w]; }
    }

    public DoomEngine(Wad w, String map) {
        this.wad = w; this.lv = new Level(w, map); this.tex = new Textures(w);
        spawnAtPlayer();
    }
    public void spawnAtPlayer() {
        viewX = lv.playerX; viewY = lv.playerY;
        viewAngle = lv.playerAngle * Math.PI / 180.0;
        viewZ = subsectorFloor(pointInSubsector(viewX, viewY)) + EYE;
    }

    int pointOnSide(double x, double y, int node) {
        double dx = x - lv.ndX[node], dy = y - lv.ndY[node];
        return ((double) lv.ndDx[node] * dy - (double) lv.ndDy[node] * dx) <= 0 ? 0 : 1;
    }
    int pointInSubsector(double x, double y) {
        int n = lv.ndX.length - 1; if (n < 0) return 0;
        while ((n & 0x8000) == 0) n = (pointOnSide(x, y, n) == 0) ? lv.ndRight[n] : lv.ndLeft[n];
        return n & 0x7fff;
    }
    int subsectorFrontSector(int ss) {
        int seg = lv.ssFirst[ss];
        int sd = (lv.segSide[seg] == 0) ? lv.ldFront[lv.segLine[seg]] : lv.ldBack[lv.segLine[seg]];
        return lv.sdSector[sd];
    }
    double subsectorFloor(int ss) { return lv.secFloor[subsectorFrontSector(ss)]; }

    public void render(int[] buf, int w, int h) {
        this.fb = buf; this.W = w; this.H = h; this.cx = w/2; this.cy = h/2; this.proj = cx;
        this.cosA = Math.cos(viewAngle); this.sinA = Math.sin(viewAngle);
        if (upper == null || upper.length != w) {
            upper = new int[w]; lower = new int[w]; spanstart = new int[h];
        }
        for (int x = 0; x < w; x++) { upper[x] = 0; lower[x] = h - 1; }
        for (int i = 0; i < buf.length; i++) buf[i] = 0xff000000;
        planeCount = 0; planeMap.clear();
        if (lv.ndX.length == 0) renderSubsector(0);   // tiny node-less map (single subsector)
        else renderNode(lv.ndX.length - 1);
        drawPlanes();
    }

    void renderNode(int n) {
        if ((n & 0x8000) != 0) { renderSubsector(n & 0x7fff); return; }
        int side = pointOnSide(viewX, viewY, n);
        renderNode((side == 0) ? lv.ndRight[n] : lv.ndLeft[n]);
        renderNode((side == 0) ? lv.ndLeft[n]  : lv.ndRight[n]);
    }
    void renderSubsector(int ss) {
        int first = lv.ssFirst[ss], cnt = lv.ssCount[ss];
        for (int i = 0; i < cnt; i++) addSeg(first + i);
    }

    // ---- visplanes ----
    Plane findPlane(byte[] flat, int height, int light) {
        String key = System.identityHashCode(flat) + "|" + height + "|" + light;
        Object o = planeMap.get(key);
        if (o != null) return (Plane) o;
        if (planeCount >= MAXPLANES) return (Plane) o; // null -> caller skips
        Plane p = planes[planeCount];
        if (p == null) { p = new Plane(W); planes[planeCount] = p; }
        p.flat = flat; p.height = height; p.light = light; p.minx = W; p.maxx = -1;
        for (int x = 0; x < W; x++) { p.top[x] = 1; p.bottom[x] = 0; } // empty
        planeCount++; planeMap.put(key, p);
        return p;
    }
    void addSpan(Plane p, int x, int t, int b) {
        if (p == null || b < t) return;
        p.top[x] = t; p.bottom[x] = b;
        if (x < p.minx) p.minx = x; if (x > p.maxx) p.maxx = x;
    }
    void drawPlanes() {
        for (int i = 0; i < planeCount; i++) makeSpans(planes[i]);
    }
    void makeSpans(Plane p) {
        int[] tp = p.top, bt = p.bottom;
        for (int x = p.minx; x <= p.maxx + 1; x++) {
            int cT, cB, pT, pB;
            if (x <= p.maxx && tp[x] <= bt[x]) { cT = tp[x]; cB = bt[x]; } else { cT = 1; cB = 0; }
            if (x > p.minx && tp[x-1] <= bt[x-1]) { pT = tp[x-1]; pB = bt[x-1]; } else { pT = 1; pB = 0; }
            for (int y = pT; y <= pB; y++) if (y < cT || y > cB) renderSpan(p, y, spanstart[y], x - 1);
            for (int y = cT; y <= cB; y++) if (y < pT || y > pB) spanstart[y] = x;
        }
    }
    void renderSpan(Plane p, int y, int x1, int x2) {
        if (x2 < x1) return;
        double denom = (y - cy); if (denom == 0) denom = 0.0001;
        double dz = proj * (p.height - viewZ) / -denom; // up-positive world; works for floor & ceil
        if (dz <= 0) return;
        byte[] lm = tex.lightMap(p.light, dz);
        double rx = sinA, ry = -cosA, inv = 1.0 / proj;
        double dirx = cosA + rx * ((x1 - cx) * inv);
        double diry = sinA + ry * ((x1 - cx) * inv);
        double wx = viewX + dz * dirx, wy = viewY + dz * diry;
        double sx = dz * rx * inv, sy = dz * ry * inv;
        byte[] flat = p.flat; int o = y * W + x1;
        for (int x = x1; x <= x2; x++) {
            int fx = ((int) Math.floor(wx)) & 63, fy = ((int) Math.floor(wy)) & 63;
            fb[o++] = tex.pal[lm[flat[fy*64 + fx] & 0xff] & 0xff];
            wx += sx; wy += sy;
        }
    }

    // ---- walls ----
    double tDepth, tSide;
    void toView(double x, double y) {
        double dx = x - viewX, dy = y - viewY;
        tDepth = dx * cosA + dy * sinA; tSide = dx * sinA - dy * cosA;
    }

    void addSeg(int seg) {
        int v1 = lv.segV1[seg], v2 = lv.segV2[seg];
        double wx1 = lv.vx[v1], wy1 = lv.vy[v1], wx2 = lv.vx[v2], wy2 = lv.vy[v2];
        toView(wx1, wy1); double dz1 = tDepth, sx1 = tSide;
        toView(wx2, wy2); double dz2 = tDepth, sx2 = tSide;

        int line = lv.segLine[seg], sideN = lv.segSide[seg];
        int fsd = (sideN == 0) ? lv.ldFront[line] : lv.ldBack[line];
        int bsd = (sideN == 0) ? lv.ldBack[line]  : lv.ldFront[line];
        int fsec = lv.sdSector[fsd];
        boolean two = lv.twoSided(line) && bsd != 0xffff;
        int bsec = two ? lv.sdSector[bsd] : -1;
        int flags = lv.ldFlags[line];

        double segLen = Math.sqrt((wx2-wx1)*(wx2-wx1) + (wy2-wy1)*(wy2-wy1));
        double uA = lv.segOff[seg] + lv.sdXoff[fsd], uB = uA + segLen;

        if (dz1 < NEAR && dz2 < NEAR) return;
        if (dz1 < NEAR) { double t=(NEAR-dz1)/(dz2-dz1); sx1+=(sx2-sx1)*t; uA+=(uB-uA)*t; dz1=NEAR; }
        else if (dz2 < NEAR) { double t=(NEAR-dz2)/(dz1-dz2); sx2+=(sx1-sx2)*t; uB+=(uA-uB)*t; dz2=NEAR; }

        double scrX1 = cx + (sx1/dz1)*proj, scrX2 = cx + (sx2/dz2)*proj;
        if (scrX1 >= scrX2) return;
        int xL = (int)Math.ceil(scrX1), xR = (int)Math.floor(scrX2);
        if (xL < 0) xL = 0; if (xR > W-1) xR = W-1; if (xL > xR) return;

        double fCeil = lv.secCeil[fsec], fFloor = lv.secFloor[fsec];
        double bCeil = two ? lv.secCeil[bsec] : 0, bFloor = two ? lv.secFloor[bsec] : 0;
        int light = lv.secLight[fsec], yoff = lv.sdYoff[fsd];
        boolean skyCeil = "F_SKY1".equals(lv.secCeilTex[fsec]);
        boolean skyFloor = "F_SKY1".equals(lv.secFloorTex[fsec]);
        byte[] flatC = tex.getFlat(lv.secCeilTex[fsec]);
        byte[] flatF = tex.getFlat(lv.secFloorTex[fsec]);
        Plane ceilPlane = (!skyCeil && flatC != null) ? findPlane(flatC, (int)fCeil, light) : null;
        Plane floorPlane = (!skyFloor && flatF != null) ? findPlane(flatF, (int)fFloor, light) : null;

        Textures.Tex midT = two ? null : tex.getTexture(lv.sdMid[fsd]);
        Textures.Tex upT  = two ? tex.getTexture(lv.sdUpper[fsd]) : null;
        Textures.Tex loT  = two ? tex.getTexture(lv.sdLower[fsd]) : null;
        double midTop = ((flags & PEGBOT)!=0 && midT!=null) ? (fFloor + midT.h) : fCeil;
        double upTop  = ((flags & PEGTOP)!=0) ? fCeil : (bCeil + (upT!=null?upT.h:0));
        double loTop  = ((flags & PEGBOT)!=0) ? fCeil : bFloor;

        double iz1 = 1.0/dz1, iz2 = 1.0/dz2, dxScr = scrX2 - scrX1;

        for (int x = xL; x <= xR; x++) {
            if (upper[x] > lower[x]) continue;
            double t = (x + 0.5 - scrX1) / dxScr;
            double iz = iz1 + (iz2 - iz1)*t;
            double depth = 1.0/iz, scale = proj*iz;
            double u = (uA*iz1 + (uB*iz2 - uA*iz1)*t) / iz;
            int yTop = (int)(cy - (fCeil  - viewZ)*scale);
            int yBot = (int)(cy - (fFloor - viewZ)*scale);
            int u0 = upper[x], lo = lower[x];

            int cb = Math.min(yTop - 1, lo);
            if (cb >= u0) { if (skyCeil) fillSky(x,u0,cb); else addSpan(ceilPlane,x,u0,cb); }
            int ft = Math.max(yBot + 1, u0);
            if (lo >= ft) { if (skyFloor) fillSky(x,ft,lo); else addSpan(floorPlane,x,ft,lo); }

            if (!two || bCeil <= bFloor) {
                drawWall(x, Math.max(yTop,u0), Math.min(yBot,lo), midT, u, midTop, yoff, light, depth, scale);
                upper[x] = H; lower[x] = -1;
            } else {
                int yTopB = (int)(cy - (bCeil - viewZ)*scale);
                int yBotB = (int)(cy - (bFloor - viewZ)*scale);
                if (bCeil < fCeil)
                    drawWall(x, Math.max(yTop,u0), Math.min(yTopB-1,lo), upT, u, upTop, yoff, light, depth, scale);
                if (bFloor > fFloor)
                    drawWall(x, Math.max(yBotB+1,u0), Math.min(yBot,lo), loT, u, loTop, yoff, light, depth, scale);
                int nu = Math.max(u0, (bCeil  < fCeil)  ? Math.max(yTop, yTopB) : yTop);
                int nl = Math.min(lo, (bFloor > fFloor) ? Math.min(yBot, yBotB) : yBot);
                upper[x] = nu; lower[x] = nl;
            }
        }
    }

    void drawWall(int x, int y0, int y1, Textures.Tex T, double u, double texTop,
                  int yoff, int light, double depth, double scale) {
        if (y1 < y0) return;
        if (y0 < 0) y0 = 0; if (y1 > H-1) y1 = H-1;
        byte[] lm = tex.lightMap(light, depth);
        if (T == null) {
            int c = tex.pal[lm[0x60] & 0xff]; int o = y0*W+x;
            for (int y=y0;y<=y1;y++){ fb[o]=c; o+=W; } return;
        }
        int tw = T.w, th = T.h;
        int tx = ((int)u % tw + tw) % tw, base = tx * th, o = y0*W + x;
        for (int y = y0; y <= y1; y++) {
            double wz = viewZ - (y - cy)/scale;
            int ty = (((int)(texTop - wz) + yoff) % th + th) % th;
            fb[o] = tex.pal[lm[T.pix[base + ty] & 0xff] & 0xff];
            o += W;
        }
    }

    void fillSky(int x, int y0, int y1) {
        if (y1 < y0) return; if (y0 < 0) y0 = 0; if (y1 > H-1) y1 = H-1;
        int o = y0*W+x; for (int y=y0;y<=y1;y++){ fb[o]=SKY; o+=W; }
    }

    public void move(double fwd, double strafe, double turn) {
        viewAngle += turn;
        double c = Math.cos(viewAngle), s = Math.sin(viewAngle);
        viewX += c*fwd + s*strafe; viewY += s*fwd - c*strafe;
        viewZ = subsectorFloor(pointInSubsector(viewX, viewY)) + EYE;
    }
}
