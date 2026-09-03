package org.junkyard.doom;

import java.awt.Frame;
import java.awt.Image;
import java.awt.Graphics;
import java.awt.Insets;
import java.awt.image.MemoryImageSource;
import java.awt.event.KeyListener;
import java.awt.event.KeyEvent;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;

/**
 * AWT 1.1 shell that runs the real DOOM BSP engine on the Dreamcast.
 * Downloads the IWAD over HTTP from the (rogue) Eden host, then blits the
 * engine's int[] framebuffer via MemoryImageSource. Class v45.3 / AWT 1.1 only.
 *
 * Launched by org.junkyard.Pwn after the service-subscription RCE.
 */
public class DoomShell extends Frame implements Runnable, KeyListener {

    static final int W = 320, H = 200, SCALE = 2;
    static final String WAD_URL = "http://eden.planetweb.com/doom.wad";
    static final String MAP = "E1M1";

    private DoomEngine eng;
    private final int[] pix = new int[W * H];
    private final boolean[] k = new boolean[6]; // fwd,back,left,right,strafeL,strafeR
    private MemoryImageSource mis;
    private Image img;
    private boolean running = true;

    public DoomShell() {
        super("DistrictCon Junkyard DOOM");
        setResizable(false);
        // fill the whole screen and force ourselves to the front over the browser
        setBackground(java.awt.Color.black);
        try {
            java.awt.Dimension scr = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
            if (scr != null && scr.width > 0) { SW = scr.width; SH = scr.height; }
        } catch (Throwable t) {}
        setLocation(0, 0);
        setSize(SW, SH);
        addKeyListener(this);
        setVisible(true);
        try { toFront(); requestFocus(); } catch (Throwable t) {}
        mis = new MemoryImageSource(W, H, pix, 0, W);
        mis.setAnimated(true);
        img = createImage(mis);
        new Thread(this).start();
    }

    int SW = W * SCALE;   // screen size (filled by Toolkit in ctor)
    int SH = H * SCALE;

    // In-browser AWT flushes through paint()/update(); draw the framebuffer here.
    public void update(Graphics g) { paint(g); }
    public void paint(Graphics g) {
        if (img == null || g == null) return;
        g.drawImage(img, 0, 0, SW, SH, this);
    }

    static byte[] download(String url) throws Exception {
        InputStream in = new URL(url).openStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1 << 20);
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }

    public void run() {
        try {
            byte[] wadBytes = download(WAD_URL);
            eng = new DoomEngine(new Wad(wadBytes), MAP);
        } catch (Throwable t) {
            t.printStackTrace();
            return;
        }
        if (img == null) img = createImage(mis);
        int frame = 0;
        while (running) {
            double fwd = (k[0] ? 12 : 0) - (k[1] ? 12 : 0);
            double str = (k[5] ? 10 : 0) - (k[4] ? 10 : 0);
            double turn = (k[3] ? 0.08 : 0) - (k[2] ? 0.08 : 0);
            eng.move(fwd, str, turn);
            eng.render(pix, W, H);
            mis.newPixels();
            // primary: drive an AWT paint() (works when getGraphics() returns null in-browser)
            repaint();
            // belt-and-suspenders: also try a direct blit, and keep us on top
            Graphics g = getGraphics();
            if (g != null) { g.drawImage(img, 0, 0, SW, SH, this); g.dispose(); }
            if ((frame++ % 50) == 0) { try { toFront(); } catch (Throwable t) {} }
            try { Thread.sleep(30); } catch (Exception e) {}
        }
    }

    private void set(int code, boolean d) {
        switch (code) {
            case KeyEvent.VK_UP:    case KeyEvent.VK_W: k[0] = d; break;
            case KeyEvent.VK_DOWN:  case KeyEvent.VK_S: k[1] = d; break;
            case KeyEvent.VK_LEFT:  case KeyEvent.VK_A: k[2] = d; break;
            case KeyEvent.VK_RIGHT: case KeyEvent.VK_D: k[3] = d; break;
            case KeyEvent.VK_COMMA: k[4] = d; break;
            case KeyEvent.VK_PERIOD: k[5] = d; break;
            case KeyEvent.VK_ESCAPE: if (d) running = false; break;
        }
    }
    public void keyPressed(KeyEvent e)  { set(e.getKeyCode(), true); }
    public void keyReleased(KeyEvent e) { set(e.getKeyCode(), false); }
    public void keyTyped(KeyEvent e)    {}

    public static void main(String[] a) { new DoomShell(); }
}
