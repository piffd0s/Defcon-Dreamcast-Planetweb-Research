package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;

/**
 * CHAIN "heapprobe" -- decisive test for the JAVA-staging path to native DOOM.
 *
 * Question: can the PersonalJava 1.1 VM hold doom.bin (418448 B) + doom1.wad
 * (4196020 B) = ~4.6 MB in byte[] at once? If yes, the NativeDoomLoader
 * byte[]+native-scan staging works with NO native-HTTP reverse engineering.
 *
 * Reports Runtime total/free, the largest single byte[] it can allocate, whether
 * it can hold the two real payloads simultaneously, and (optionally) downloads
 * the real doom1.wad over HTTP to prove a streamed fetch fits. POSTs results to
 * eden /heap. Class v45.3 (PersonalJava 1.1.8) -- only 1.1 APIs (total/free
 * Memory + gc; NO maxMemory which is JDK1.4).
 */
public class HeapProbe extends Service {

    static final int DOOM = 418448;       // doom.bin
    static final int WAD  = 4196020;      // doom1.wad

    public ServiceInfo getInfo() {
        return new ServiceInfo("JunkyardHeap", "1.0", "DistrictCon", Junk.BASE);
    }

    static long total() { return Runtime.getRuntime().totalMemory(); }
    static long free()  { Runtime.getRuntime().gc(); return Runtime.getRuntime().freeMemory(); }

    public void run() {
        Junk.banner("CHAIN heapprobe -- can the VM hold doom.bin + doom1.wad (~4.6MB)?");
        StringBuffer r = new StringBuffer();
        r.append("# VM heap probe\n");
        r.append("totalMemory=").append(total()).append("\n");
        r.append("freeMemory(after gc)=").append(free()).append("\n");

        // largest single byte[] (512KB steps, free between)
        int best = 0;
        for (int mb2 = 1; mb2 <= 16; mb2++) {       // 0.5 MB .. 8 MB
            int sz = mb2 * 512 * 1024;
            try { byte[] b = new byte[sz]; b[sz-1] = 1; best = sz; b = null; Runtime.getRuntime().gc(); }
            catch (Throwable t) { break; }
        }
        r.append("largest_single_byte[]=").append(best).append(" (").append(best/1024).append(" KB)\n");

        // THE decisive test: hold both real payloads at once
        String both;
        byte[] a = null, c = null;
        try {
            a = new byte[DOOM]; a[DOOM-1] = 1;
            c = new byte[WAD];  c[WAD-1]  = 1;
            both = "YES (allocated doom.bin+doom1.wad simultaneously = " + (DOOM+WAD) + " B)";
        } catch (Throwable t) {
            both = "NO (" + t + ")";
        }
        a = null; c = null; Runtime.getRuntime().gc();
        r.append("can_hold_both_payloads=").append(both).append("\n");
        r.append("freeMemory(end)=").append(free()).append("\n");

        // POST the DECISIVE results FIRST -- a big download can OOM-thrash the VM and
        // wedge it, so never let it block the report.
        Eden.println(r.toString());
        Junk.httpPost(Junk.BASE + "/heap", r.toString());
        Eden.println("[heapprobe] posted decisive results to /heap");

        // best-effort extra: try the real 4MB download (may hang/OOM -- already reported above)
        try {
            byte[] w = Junk.httpGet(Junk.BASE + "/doom.wad");
            Junk.httpPost(Junk.BASE + "/heap", "downloaded_doom.wad=" + (w == null ? "null" : (w.length + " B OK")) + "\n");
        } catch (Throwable t) {
            Junk.httpPost(Junk.BASE + "/heap", "downloaded_doom.wad=FAIL " + t + "\n");
        }
    }
}
