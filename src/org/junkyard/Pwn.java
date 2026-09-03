package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;

/**
 * CHAIN "jdoom": real WAD/BSP DOOM in the browser's Java VM.
 * Delivered by the Eden service-subscription RCE; pulls the DOOM engine
 * (doom.jar) via the manifest Jar-Files attribute, then launches it.
 * No SecurityManager -> fully privileged. Class v45.3 (PersonalJava 1.1.8).
 */
public class Pwn extends Service {
    static final String BASE = "http://eden.planetweb.com";

    public ServiceInfo getInfo() { return new ServiceInfo("JunkyardDoom", "1.0", "DistrictCon", BASE); }

    public void run() {
        Junk.banner("CHAIN jdoom -- real DOOM (WAD/BSP) in the Java VM");
        Junk.prove();
        try {
            Eden.println("[*] loading DOOM engine (doom.jar via Jar-Files) ...");
            Class c = Class.forName("org.junkyard.doom.DoomShell");
            Eden.println("[+] engine class loaded: " + c.getName());
            c.newInstance();   // DoomShell downloads the IWAD and starts rendering
            Eden.println("[+] DOOM started");
        } catch (Throwable t) {
            Eden.println("[!] DOOM launch failed: " + t);
            t.printStackTrace();
        }
    }
}
