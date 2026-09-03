package org.junkyard.doom;

import java.applet.Applet;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.image.MemoryImageSource;
import java.awt.event.KeyListener;
import java.awt.event.KeyEvent;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;

/**
 * Real WAD/BSP DOOM as a Java APPLET, so the PlanetWeb browser renders it INLINE
 * in the page (click-to-launch). Downloads the IWAD over HTTP, runs the same
 * DoomEngine, blits via MemoryImageSource into the applet area. Class v45.3 /
 * PersonalJava 1.1 / AWT 1.1.
 *
 * Embedded with:  <applet code="org.junkyard.doom.DoomApplet" archive="doom.jar"
 *                  width=320 height=200><param name=wad value="...doom.wad"></applet>
 */
public class DoomApplet extends Applet implements Runnable, KeyListener {

    static final int W = 320, H = 200, MAP_DEFAULT = 0;
    private DoomEngine eng;
    private final int[] pix = new int[W * H];
    private final boolean[] k = new boolean[6];
    private MemoryImageSource mis;
    private Image img;
    private Thread th;
    private boolean running = true;
    private String status = "loading WAD...";

    public void init() {
        addKeyListener(this);
        mis = new MemoryImageSource(W, H, pix, 0, W);
        mis.setAnimated(true);
        img = createImage(mis);
        requestFocus();
    }

    public void start() {
        running = true;
        if (th == null) { th = new Thread(this); th.start(); }
    }
    public void stop() { running = false; th = null; }

    static byte[] dl(String u) throws Exception {
        InputStream in = new URL(u).openStream();
        ByteArrayOutputStream b = new ByteArrayOutputStream(1 << 20);
        byte[] buf = new byte[8192]; int n;
        while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
        in.close(); return b.toByteArray();
    }

    public void run() {
        try {
            String wad = getParameter("wad");
            if (wad == null) wad = "http://eden.planetweb.com/doom.wad";
            String map = getParameter("map"); if (map == null) map = "E1M1";
            eng = new DoomEngine(new Wad(dl(wad)), map);
            status = null;
        } catch (Throwable t) {
            status = "DOOM load failed: " + t;
            repaint(); t.printStackTrace(); return;
        }
        if (img == null) img = createImage(mis);
        while (running) {
            double fwd = (k[0] ? 12 : 0) - (k[1] ? 12 : 0);
            double str = (k[5] ? 10 : 0) - (k[4] ? 10 : 0);
            double turn = (k[3] ? 0.08 : 0) - (k[2] ? 0.08 : 0);
            eng.move(fwd, str, turn);
            eng.render(pix, W, H);
            mis.newPixels();
            Graphics g = getGraphics();
            if (g != null) { blit(g); g.dispose(); }
            try { Thread.sleep(33); } catch (Exception e) {}
        }
    }

    private void blit(Graphics g) {
        int w = getSize().width, h = getSize().height;
        if (img != null) g.drawImage(img, 0, 0, w > 0 ? w : W, h > 0 ? h : H, this);
    }

    public void update(Graphics g) { paint(g); }
    public void paint(Graphics g) {
        if (status != null) { g.drawString(status, 8, 20); return; }
        blit(g);
    }

    private void set(int c, boolean d) {
        switch (c) {
            case KeyEvent.VK_UP:    case KeyEvent.VK_W: k[0] = d; break;
            case KeyEvent.VK_DOWN:  case KeyEvent.VK_S: k[1] = d; break;
            case KeyEvent.VK_LEFT:  case KeyEvent.VK_A: k[2] = d; break;
            case KeyEvent.VK_RIGHT: case KeyEvent.VK_D: k[3] = d; break;
            case KeyEvent.VK_COMMA:  k[4] = d; break;
            case KeyEvent.VK_PERIOD: k[5] = d; break;
        }
    }
    public void keyPressed(KeyEvent e)  { set(e.getKeyCode(), true); }
    public void keyReleased(KeyEvent e) { set(e.getKeyCode(), false); }
    public void keyTyped(KeyEvent e)    {}
}
