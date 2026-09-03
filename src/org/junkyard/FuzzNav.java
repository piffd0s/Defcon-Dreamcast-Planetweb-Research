package org.junkyard;

import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;

/**
 * CHAIN "fuzz": navigates the browser to a PER-BOOT-UNIQUE URL so the served
 * fuzz page (and its mutated images) is always a cache MISS -- defeats the
 * browser's persistent VMU page cache WITHOUT wiping the VMU (which would also
 * erase the saved network config and break auto-connect).
 *
 * Uniqueness uses currentTimeMillis() + identity hashCode (heap-address-derived,
 * differs every boot even if the emulated RTC is fixed). eden_mitm serves any
 * /fz/... URL with the current batch page (www/_fuzzpage.html).
 */
public class FuzzNav extends Service {
    public ServiceInfo getInfo() { return new ServiceInfo("JunkyardFuzz", "1.0", "DistrictCon", Junk.BASE); }

    public void run() {
        Junk.banner("CHAIN fuzz -- parser fuzz navigation");
        String tag = Long.toString(System.currentTimeMillis())
                   + "_" + Integer.toHexString(new Object().hashCode());
        Junk.openURL(Junk.BASE + "/fz/p" + tag + ".html");
    }
}
