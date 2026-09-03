#!/usr/bin/env python3
"""Generate the DistrictCon Junkyard vulnerability-research / pentest report PDF."""
import os
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                                PageBreak, Image, HRFlowable, KeepTogether)

ROOT = "/media/adversary/Storage/dc_browser_extract"
OUT  = ROOT + "/poc/DistrictCon_Junkyard_PlanetWeb_Report.pdf"

SEVCOL = {"CRITICAL":colors.HexColor("#8e0000"), "HIGH":colors.HexColor("#c0392b"),
          "MEDIUM":colors.HexColor("#d68910"), "LOW":colors.HexColor("#2e86c1"),
          "INFO":colors.HexColor("#7f8c8d")}

ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=16, spaceBefore=14, spaceAfter=8,
                    textColor=colors.HexColor("#1a1a2e"))
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=12.5, spaceBefore=10, spaceAfter=4,
                    textColor=colors.HexColor("#16213e"))
BODY = ParagraphStyle("BODY", parent=ss["BodyText"], fontSize=9.5, leading=13, alignment=TA_JUSTIFY)
SMALL= ParagraphStyle("SMALL", parent=ss["BodyText"], fontSize=8, leading=10, textColor=colors.grey)
CODE = ParagraphStyle("CODE", parent=ss["Code"], fontSize=7.6, leading=9.5,
                      backColor=colors.HexColor("#f4f4f4"), borderPadding=4, leftIndent=4)
LBL  = ParagraphStyle("LBL", parent=BODY, fontName="Helvetica-Bold")

S = []
def p(t, st=BODY): S.append(Paragraph(t, st))
def code(t): S.append(Paragraph(t.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\n","<br/>"), CODE))
def sp(h=6): S.append(Spacer(1, h))
def hr(): S.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#cccccc"), spaceBefore=6, spaceAfter=6))

def img(path, w=6.2*inch):
    if os.path.exists(path):
        from PIL import Image as PImage
        iw, ih = PImage.open(path).size
        S.append(Image(path, width=w, height=w*ih/iw)); S.append(Spacer(1,3))

# ---------------- cover ----------------
sp(60)
p("VULNERABILITY RESEARCH &amp; PENETRATION TEST REPORT", ParagraphStyle("T",parent=H1,fontSize=22,alignment=TA_CENTER,textColor=colors.HexColor("#8e0000")))
sp(6)
p("Sega Dreamcast &mdash; PlanetWeb Internet Browser v3.0 (USA)", ParagraphStyle("ST",parent=H1,fontSize=14,alignment=TA_CENTER,textColor=colors.HexColor("#16213e")))
sp(30)
cover = [["Target", "PlanetWeb / “Eden” Internet Browser v3.0 (Game ID T31901N)"],
         ["Platform", "Sega Dreamcast (Hitachi SH-4, PersonalJava 1.1.8)"],
         ["Engagement", "DistrictCon Junkyard — dead/EOL hardware security research"],
         ["Assessment type", "Reverse engineering, vulnerability research, exploit development"],
         ["Validation", "Live, on emulated Dreamcast (Flycast, real BIOS) + SH-4 GDB"],
         ["Date", "June 2026"],
         ["Classification", "Authorized research — own hardware / competition"]]
t = Table(cover, colWidths=[1.6*inch, 4.6*inch])
t.setStyle(TableStyle([("FONT",(0,0),(-1,-1),"Helvetica",9.5),("FONT",(0,0),(0,-1),"Helvetica-Bold",9.5),
                       ("TEXTCOLOR",(0,0),(0,-1),colors.HexColor("#16213e")),
                       ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white,colors.HexColor("#f4f4f7")]),
                       ("BOX",(0,0),(-1,-1),0.5,colors.grey),("INNERGRID",(0,0),(-1,-1),0.3,colors.lightgrey),
                       ("VALIGN",(0,0),(-1,-1),"TOP"),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
S.append(t)
sp(20)
p("This report documents a full security assessment of the Sega Dreamcast PlanetWeb "
  "Internet Browser v3.0. Findings range from a confirmed, live, unauthenticated remote "
  "code-execution chain to a dynamically-validated native memory-corruption primitive. All "
  "testing was performed against the assessor's own extracted disc image in an emulator.", SMALL)
S.append(PageBreak())

# ---------------- exec summary ----------------
p("1. Executive Summary", H1)
p("The PlanetWeb “Eden” browser auto-connects on boot to Planetweb's back-end servers "
  "over <b>plaintext HTTP</b>, at domains that are now <b>expired</b>. The client trusts those "
  "servers completely: it downloads and runs <b>unsigned Java code</b> they reference, with "
  "<b>no SecurityManager</b> installed. Whoever answers for the dead domains therefore achieves "
  "<b>unauthenticated remote code execution</b> on the console — by design, no memory "
  "corruption required. This was <b>confirmed live</b>: a rogue server walked the emulated "
  "Dreamcast through login → discovery → subscription → JAR download → execution, "
  "and the payload took over the browser and ran a full DOOM engine inside the device's Java VM.")
sp(4)
p("Beyond the design-level RCE, reverse engineering of the native SH-4 engine (1ST_READ.BIN) "
  "identified the Java→native command bridge and a <b>missing-bounds-check memory copy</b> "
  "(setRawDeviceID) that was <b>dynamically confirmed to corrupt memory and fault the CPU</b> "
  "under a debugger. An <b>autonomous in-browser fuzzing campaign</b> (a patched emulator that "
  "savestates the online session for ~2-second crash recovery, AFL-style mutators, and a "
  "self-recovering orchestrator) then drove the native decoders to <b>real CPU faults</b>: a "
  "deterministically-reproducible <b>JPEG Huffman-table heap overflow</b>, plus PNG and GIF "
  "dimension/length overflows. Source-level review of the Java attack surface and GDB-stub "
  "harnesses against the JS engine and class verifier scoped the remaining vectors — the image "
  "decoders and the Eden class-load are the soft targets; the JS engine and XML/class parsers "
  "proved comparatively hardened.")
sp(6)
# severity tally
tally = [["Critical","High","Medium","Low/Info"],["1","7","3","7"]]
tt = Table(tally, colWidths=[1.55*inch]*4)
tt.setStyle(TableStyle([("FONT",(0,0),(-1,-1),"Helvetica-Bold",10),("ALIGN",(0,0),(-1,-1),"CENTER"),
    ("BACKGROUND",(0,0),(0,0),SEVCOL["CRITICAL"]),("BACKGROUND",(1,0),(1,0),SEVCOL["HIGH"]),
    ("BACKGROUND",(2,0),(2,0),SEVCOL["MEDIUM"]),("BACKGROUND",(3,0),(3,0),SEVCOL["LOW"]),
    ("TEXTCOLOR",(0,0),(-1,0),colors.white),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
    ("BOX",(0,0),(-1,-1),0.5,colors.grey)]))
S.append(tt)

# ---------------- findings summary ----------------
p("2. Findings Overview", H1)
rows = [["ID","Finding","Severity","Status"],
 ["F-01","Unauthenticated RCE via Eden service-subscription chain","CRITICAL","Confirmed (live)"],
 ["F-02","No SecurityManager — java.policy unenforced; code fully privileged","HIGH","Confirmed"],
 ["F-03","Downloaded service JARs are not signature-verified","HIGH","Confirmed"],
 ["F-04","Plaintext HTTP to expired domains (trivial MITM / takeover)","HIGH","Confirmed"],
 ["F-05","Manifest “Jar-Files” pulls arbitrary additional remote code","HIGH","Confirmed"],
 ["F-06","XXE-capable XML parsers (static) — NOT exploitable at runtime","LOW","Tested (negative)"],
 ["F-07","Native setRawDeviceID unbounded memcpy → BSS overflow","HIGH","Confirmed (live, GDB)"],
 ["F-08","Browser image-decoder memory corruption (parser surface)","HIGH","Confirmed (live faults)"],
 ["F-09","Privileged FLASH/VMU writes (persistence / brick)","LOW","Confirmed (static)"],
 ["F-10","Latent debug-console command channel (disabled on retail)","INFO","Confirmed (static)"],
 ["F-11","Native setSecurityFile is a no-op (hardening gap)","INFO","Confirmed (static)"],
 ["F-12","JPEG DHT Huffman-count overflow → SH-4 CPU fault","HIGH","Confirmed (live, deterministic)"],
 ["F-13","PNG decoder IHDR-dimension + chunk-length overflows","MEDIUM","Confirmed (live)"],
 ["F-14","GIF/LZW image-dimension + raster overflow / hangs","MEDIUM","Confirmed (live)"],
 ["F-15","HTTP request builder: unbounded %s host/cookie sprintf","MEDIUM","Confirmed (static)"],
 ["F-16","JavaScript engine: robust (no RCE); deep-nest DoS only","LOW","Tested (negative + DoS)"],
 ["F-17","PersonalJava class verifier: constant_pool_count OOB read","LOW","Confirmed (live, GDB)"],
 ["F-18","Additional native parser surface (email POP3/SMTP, SWF)","INFO","Surface mapped"]]
ft = Table(rows, colWidths=[0.5*inch,3.5*inch,0.95*inch,1.25*inch], repeatRows=1)
sty = [("FONT",(0,0),(-1,-1),"Helvetica",8.3),("FONT",(0,0),(-1,0),"Helvetica-Bold",8.6),
       ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16213e")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
       ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f4f4f7")]),
       ("BOX",(0,0),(-1,-1),0.5,colors.grey),("INNERGRID",(0,0),(-1,-1),0.3,colors.lightgrey),
       ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]
for i,r in enumerate(rows[1:],1):
    sty.append(("TEXTCOLOR",(2,i),(2,i),SEVCOL.get(r[2],colors.black)))
    sty.append(("FONT",(2,i),(2,i),"Helvetica-Bold",8.3))
ft.setStyle(TableStyle(sty)); S.append(ft)

# ---------------- scope/method ----------------
p("3. Scope, Methodology &amp; Environment", H1)
p("<b>Scope.</b> The retail GD-ROM image of Internet Browser v3.0 (USA): the native SH-4 "
  "executable (1ST_READ.BIN), the bundled PersonalJava “Eden” client and libraries "
  "(planetweb.jar, openbrew.jar, pjfs.jar, discovery.jar) and the device runtime (classes.zip), "
  "and the client's network protocol.")
p("<b>Methodology.</b> (1) Disc extraction and ISO9660 file recovery. (2) Java decompilation "
  "(CFR) and manual review of the Eden client + libraries. (3) Protocol reconstruction and a "
  "rogue-server implementation. (4) Native SH-4 reverse engineering of 1ST_READ.BIN (Capstone). "
  "(5) Dynamic validation in a debug build of Flycast with a live SH-4 GDB stub and a custom "
  "GDB-remote client. (6) An autonomous, self-recovering in-browser fuzzing campaign across the "
  "image/markup/script decoders (AFL-style mutation + online-save-state crash recovery), plus "
  "GDB-stub in-process harnesses for the JS engine and Java class verifier. (7) Source-level Java "
  "review for non-memory-safety RCE classes (deserialization, reflection, XXE).")
p("<b>Environment.</b> Flycast (built from source with the GDB server enabled), real Dreamcast "
  "BIOS, broadband-adapter/modem networking redirected via a rogue DNS to the assessor's host "
  "running the rogue Eden server on port 80.")
S.append(PageBreak())

# ---------------- detailed findings ----------------
p("4. Detailed Findings", H1)

def finding(fid, title, sev, status, affected, desc, evidence, impact, repro, remed):
    blk=[]
    blk.append(Paragraph("%s &nbsp;&mdash;&nbsp; %s" % (fid, title), H2))
    meta=[[Paragraph("<b>Severity</b>",SMALL),Paragraph("<b>Status</b>",SMALL),Paragraph("<b>Affected</b>",SMALL)],
          [Paragraph('<font color="%s"><b>%s</b></font>'%(SEVCOL[sev].hexval(),sev),BODY),
           Paragraph(status,BODY),Paragraph(affected,BODY)]]
    mt=Table(meta,colWidths=[1.0*inch,1.6*inch,3.6*inch])
    mt.setStyle(TableStyle([("BOX",(0,0),(-1,-1),0.3,colors.lightgrey),("INNERGRID",(0,0),(-1,-1),0.3,colors.lightgrey),
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eef")),("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
    blk.append(mt); blk.append(Spacer(1,4))
    S.append(KeepTogether(blk))
    p("<b>Description.</b> "+desc)
    if evidence: p("<b>Evidence.</b> "+evidence)
    p("<b>Impact.</b> "+impact)
    if repro: p("<b>Reproduction.</b> "+repro)
    p("<b>Remediation.</b> "+remed)
    hr()

finding("F-01","Unauthenticated Remote Code Execution via the Eden service-subscription chain",
 "CRITICAL","Confirmed (executed live on emulated hardware)","Eden client: LoginManager, DiscoveryService, ServiceManager, JarClassLoader",
 "On boot the Eden client fetches <font face='Courier'>http://eden.planetweb.com/edenclient.conf</font> to learn a login URL, POSTs an XML login, and reads a server-supplied <i>discovery URL</i> from the response. Discovery returns service names and subscription URLs; subscription returns a <i>service download URL</i>. <font face='Courier'>ServiceManager.loadService()</font> downloads that JAR, reads its <font face='Courier'>Main-Class</font>, instantiates it and runs it on a thread. Every one of those URLs is taken verbatim from server-controlled XML. Because the Planetweb domains are expired and all traffic is plaintext HTTP, anyone who answers for the host controls the entire flow.",
 "A rogue server (≈300 lines) reproduced the exact wire format (namespace-prefixed XML, status attributes, injected URLs). Live on Flycast the guest walked the full chain (server log: <font face='Courier'>edenclient.conf → login → discovery → subscribe → pwn.jar</font>) and the downloaded service executed — it then hijacked the browser to an attacker page (see §6).",
 "Full unauthenticated code execution in the browser's JVM on any console that connects, with no user interaction and no memory-corruption bug. On real hardware the attacker only needs to answer DNS for the dead domains (e.g. via the DreamPi setups the community already uses).",
 "Run the rogue DNS + Eden server; point the console's DNS at it; boot the browser. The chain fires automatically after the network comes up.",
 "Sign service descriptors/JARs; pin server identity with TLS + certificate validation; do not derive executable-code URLs from unauthenticated responses. (Unfixable in practice on EOL hardware — mitigate by not connecting these browsers to untrusted networks.)")

finding("F-02","No SecurityManager — the bundled security policy is never enforced",
 "HIGH","Confirmed","Eden runtime; lib/security/java.policy",
 "The disc ships a <font face='Courier'>java.policy</font> granting <font face='Courier'>AllPermission</font> to *.planetweb.com code, implying an applet sandbox. In practice <b>no SecurityManager is ever installed</b> (no <font face='Courier'>setSecurityManager</font> anywhere in the client; JarClassLoader guards every check with <font face='Courier'>if (sm != null)</font>). The policy file is dead configuration.",
 "Static review of the decompiled client; the policy grants and the absent SecurityManager.",
 "Any code loaded by the browser — via F-01, or any Java applet on any visited page — runs fully privileged: arbitrary file, network and native-bridge access. This is what makes F-01 a clean RCE rather than a sandboxed applet.",
 None,
 "Install and configure a SecurityManager; enforce the shipped policy. (EOL: not patchable.)")

finding("F-03","Downloaded service JARs are not signature-verified",
 "HIGH","Confirmed","org.openbrew.util.zip.JarResource; ServiceManager",
 "<font face='Courier'>JarResource.load()</font> fetches a JAR over HTTP and unzips it; no signature, checksum or certificate is checked before <font face='Courier'>JarClassLoader.defineClass()</font> runs it. The manifest is read only for <font face='Courier'>Main-Class</font>/<font face='Courier'>Jar-Files</font>.",
 "Static review (no verify/signature/certificate logic in JarResource).",
 "Any unsigned attacker JAR is accepted and executed (enables F-01/F-05).", None,
 "Require signed JARs verified against a pinned key before loading.")

finding("F-04","Plaintext HTTP to expired domains — trivial MITM / domain takeover",
 "HIGH","Confirmed","EdenConfiguration; all client network I/O",
 "All Eden traffic is HTTP (no TLS) to <font face='Courier'>eden.planetweb.com</font> and related hosts, which are no longer registered. There is no server authentication. An on-path attacker, a malicious DNS, or simply re-registering the domain yields full control of every client response.",
 "EdenConfiguration defaults (edenserver=eden.planetweb.com:80, loginurl=http://...); Connection uses HttpURLConnection over HTTP.",
 "Provides the delivery channel for F-01. Lowers the bar from “on-path attacker” to “anyone” (expired domains).", None,
 "TLS with pinned certificates; reject plaintext. (EOL: unpatchable.)")

finding("F-05","Manifest “Jar-Files” pulls arbitrary additional remote code",
 "HIGH","Confirmed (used in live demo)","ServiceManager.loadService()",
 "A service JAR's manifest may list <font face='Courier'>Jar-Files:</font> with arbitrary absolute URLs; ServiceManager downloads each and adds it to the same class loader before running the service.",
 "Used in the live DOOM demo: the service manifest declared <font face='Courier'>Jar-Files: http://eden.planetweb.com/doom.jar</font>, pulling a second-stage engine JAR which was then run.",
 "Modular second-stage payload delivery; arbitrary code from arbitrary hosts.", None,
 "Disallow remote Jar-Files / restrict to signed same-origin resources.")

finding("F-06","XXE-capable XML parsers (static) — not exploitable at runtime",
 "LOW","Tested live (negative)","com.planetweb.xml.XMLParser (DOM); DiscoveryDocument (SAX)",
 "Server responses are parsed with <font face='Courier'>DocumentBuilderFactory</font> (validating=false only) and SAX, with <b>no</b> disabling of external/general entities or DTDs in source — the classic XXE-candidate pattern. <font face='Courier'>LoginResponseHandler</font>/<font face='Courier'>DiscoveryResponseHandler</font> route through this parser, and the rogue server controls those bodies.",
 "The XXE was weaponized in the rogue server (external-entity SSRF probe + OOB parameter-entity file-exfil DTD, injected into the login response) and tested live across two fresh connects. <b>Result: not exploitable.</b> The embedded PersonalJava XML build never fetched the external entity (no out-of-band request), and injecting a DOCTYPE broke the login parse (the chain halted at POST /login). The unhardened source did not translate to a runtime XXE.",
 "Only effect observed was a login-parse DoS, which presupposes already controlling the Eden server (i.e. already RCE via F-01). No file disclosure / SSRF on this build.", None,
 "Still: disable DTDs/external entities (FEATURE_SECURE_PROCESSING) as defense-in-depth.")

finding("F-07","Native setRawDeviceID() performs an unbounded copy into a fixed BSS buffer",
 "HIGH","Confirmed live under GDB (memory corruption → CPU fault)","1ST_READ.BIN: sendCommand handler 0x8c04e0dc → memcpy 0x8c07d680",
 "The Java→native bridge funnels through <font face='Courier'>NativeSystemInterface.sendCommand(int,Object,Object)</font>; the dispatcher was located at 0x8c04dfa0 and fully mapped (all 27 commands). Command 100 (setRawDeviceID) executes "
 "<font face='Courier'>memcpy(0x8c29abe6, attacker_bytes, len)</font> into the 8-byte device-ID field with <b>no bound check</b> (length is the attacker array length, not a constant).",
 "Live: a privileged service (delivered via F-01) called setRawDeviceID with an over-length array; under the SH-4 GDB stub the device-ID global and the adjacent object pointer at +0x42 (0x8c29ac28) were overwritten and the CPU faulted (“Fatal: SH4 exception”). The dispatcher, handlers, and 28 directly-called function-pointer globals were recovered statically and verified against live memory.",
 "A fixed-address global/BSS overflow with attacker-controlled length and content — a native memory-corruption primitive. Weaponizing to reliable arbitrary PC is constrained by an unfavorable BSS layout (see §7); the primitive itself is proven.",
 "Deliver the <font face='Courier'>overflow</font> chain; observe corruption/fault via the GDB stub (port 3263).",
 "Bounds-check native array copies against the destination size. (EOL: unpatchable.)")

finding("F-08","Browser image-decoder memory corruption (parser attack surface)",
 "HIGH","Confirmed (live faults) via autonomous fuzzing","1ST_READ.BIN: JPEG ~0x8c1b3xxx, GIF/LZW 0x8c013xxx, PNG (libpng+zlib), flex HTML lexer 0x8c190a60, JS engine 0x8c18b6b0",
 "The native engine decodes attacker-supplied content fetched from the network (a single served <font face='Courier'>&lt;img&gt;</font> is enough): a libjpeg-derived JPEG decoder, a GIF/LZW decoder, a libpng-derived PNG decoder, a flex HTML lexer, and a JavaScript engine. An <b>autonomous in-browser fuzzing campaign</b> (see §6.1) drove these to <b>real SH-4 CPU faults and hangs</b> — multiple memory-corruption bugs, detailed in F-12 (JPEG), F-13 (PNG), F-14 (GIF). This is the most attacker-reachable path to native, full-speed code execution (the classic Dreamcast-browser homebrew vector).",
 "Decoder/error strings located and cross-referenced (e.g. “bad Huffman code”, libpng “Invalid image size in IHDR”, “scanner input buffer overflow”); dozens of crashing inputs banked with per-input attribution and auto-saved culprits.",
 "Native memory corruption reachable by content alone — the primitive class for full native code execution on the console.", None,
 "Memory-safe decoders / strict bounds + dimension validation. (EOL: unpatchable.)")

finding("F-09","Privileged native FLASH and VMU writes (persistence / brick)",
 "LOW","Confirmed (static)","sendCommand 100 (FLASH), 1003 vmuPutFile",
 "Post-RCE, privileged code reaches native commands that write the device ID to FLASH (cmd 100) and write named files to the VMU (cmd 1003) with attacker-controlled content.",
 "Dispatcher map + handler analysis.",
 "Persistence and potential bricking of system flash / corruption of save data.", None,
 "N/A (post-exploitation capability).")

finding("F-10","Latent debug-console command channel (not enabled on retail)",
 "INFO","Confirmed (static)","Eden processCommandLineArgs; DebugConsole; Debug.setDebugServer",
 "A <font face='Courier'>debug:host:port</font> launch argument routes the client's debug stream to a remote server, and a <font face='Courier'>DebugConsole</font> reads and executes typed commands. The retail autostart passes only <font face='Courier'>debug</font> (verbose logging, no host:port), so the remote channel and console are <b>not active</b> on the shipped disc. The bundled HttpServer/DebugServer/MulticastServer classes are unreachable test code (only in <font face='Courier'>main()</font>).",
 "Eden.processCommandLineArgs (bUseDebugServer only set when arg contains ':'); AUTOSTART.TXT.",
 "No live impact on retail; a debug/developer build with <font face='Courier'>debug:host:port</font> would expose a remote command channel.", None,
 "Strip debug console/server from release builds.")

finding("F-11","Native setSecurityFile() is a no-op",
 "INFO","Confirmed (static)","1ST_READ.BIN sendCommand 111",
 "Command 111 (setSecurityFile), expected to install a native security policy, branches straight to the function epilogue and returns — it does nothing.",
 "Handler disassembly (111 and 3 share the epilogue at 0x8c04e626).",
 "Any intended native-side policy enforcement for the byte[] is absent (hardening gap; complements F-02).", None,
 "Implement/verify native policy handling.")

finding("F-12","JPEG DHT Huffman-count overflow → SH-4 CPU fault (deterministic)",
 "HIGH","Confirmed live (deterministic, reproducible)","1ST_READ.BIN libjpeg-derived JPEG decoder; jpeg_std_message_table @0x8c1b3cc8",
 "A served JPEG whose DHT (Define Huffman Table) marker declares 16 BITS counts summing far beyond 256 (PoC: 2107) with only a couple of HUFFVAL bytes present. Stock libjpeg rejects <font face='Courier'>count &gt; 256</font> with JERR_BAD_HUFF_TABLE — the message string is even present in ROM (table entry [8]) — but PlanetWeb's build is <b>missing that bounds check</b>: it accepts the input and copies ~2107 attacker bytes into a fixed <font face='Courier'>huffval[256]</font> table = an ~1851-byte BSS overflow (attacker-controlled content and length).",
 "Found by the autonomous fuzzer; reduced to a deterministic 3-image sequence (ff_36→37→38) that faults 100% of the time (Flycast: “Fatal: SH4 exception”). Bisection shows the overflow corrupts writable memory silently and the fault manifests on a following decode — textbook controllable heap/BSS corruption. PoC + analysis: crashes/FINDING_jpeg_dht_overflow_FAULT.md.",
 "<b>The strongest browser-native code-execution candidate:</b> a single served image, no Java, no privilege, yielding an attacker-controlled fixed-address overflow that produces a real CPU exception.",
 "Serve the pinned 3-image sequence; the browser faults on decode (no user interaction beyond viewing).",
 "Bounds-check Huffman counts (≤256) before populating the table. (EOL: unpatchable.)")

finding("F-13","PNG decoder: IHDR-dimension and chunk-length overflows",
 "MEDIUM","Confirmed live","1ST_READ.BIN libpng-derived PNG decoder + zlib 1.1.3",
 "The PNG decoder (libpng-derived; ROM strings “Invalid image size in IHDR”, “Invalid bit depth in IHDR”) does not adequately validate IHDR/chunk fields. (a) IHDR width = 0x7FFFFFFF, height = 1 (CRC made valid) drives a ~2-billion-pixel row → hang/over-allocation. (b) A chunk length of 0xFFFFFFFF causes an over-read / out-of-bounds processing. Found via AFL-style interesting-value injection into a CRC-corrected PNG.",
 "Banked culprits crashes/PNGHANG_ff085.png (IHDR dims) and chunk-length over-read variants; writeup crashes/FINDING_png_ihdr_dimension.md. Reachable by a single served &lt;img src=x.png&gt;.",
 "Native memory corruption / DoS in a second decoder (the width×channels row-buffer size on 32-bit SH-4 is a classic integer-overflow → undersized-alloc shape, cf. CVE-2004-0599).", None,
 "Validate IHDR dimensions/bit-depth and chunk lengths against limits. (EOL: unpatchable.)")

finding("F-14","GIF/LZW decoder: image-dimension / raster overflow and LZW hangs",
 "MEDIUM","Confirmed live","1ST_READ.BIN GIF/LZW decoder 0x8c013000–0x8c015400",
 "The GIF decoder accepts an out-of-range LZW minimum code size (e.g. 12; legal 2–8) → decoder hang; and an image-block whose dimensions far exceed the logical screen (e.g. 2048×2048 in a 185×75 canvas) → raster out-of-bounds write → SH-4 fault. The codesize byte and image dimensions are unvalidated.",
 "Banked culprits incl. GIFFAULT_ff096.gif (dimension overflow) and HANG_gif_lzw_codesize12.gif; writeups crashes/FINDING_gif_lzw_hang.md, FINDING_gif_dimension_overflow.md.",
 "A third content-reachable native memory-corruption / DoS surface.", None,
 "Validate LZW code size (2–8) and image dimensions vs the raster buffer. (EOL: unpatchable.)")

finding("F-15","HTTP request builder: unbounded %s host/cookie formatting",
 "MEDIUM","Confirmed (static); runtime trigger constrained","1ST_READ.BIN request builder; format strings @0x8c17f9e4 (GET), @0x8c17fa8c (Cookie)",
 "The native HTTP request constructor formats the URL <b>path</b> with a length-bounded specifier (<font face='Courier'>%.*s</font>) but the <b>host</b> and <b>cookie</b> with <b>unbounded</b> <font face='Courier'>%s</font> (e.g. <font face='Courier'>'GET %s//%s%.*s HTTP/1.0'</font>, <font face='Courier'>'Cookie: %s'</font>). A long hostname or cookie formatted into a fixed request buffer is the classic embedded-browser overflow shape.",
 "Sink located and confirmed statically (call sites 0x8c03a184 / 0x8c03a410). Dynamic triggering on this build was constrained: the browser did not echo our Set-Cookie back (so Cookie:%s was not reachable from the server side), and hostnames are DNS-length-limited (~255B). A definitive confirmation needs a GDB-stub harness on the builder (deferred).",
 "Potential native stack/heap overflow during request construction; reachable in principle via long host/redirect or a cookie path.", None,
 "Use bounded formatting (snprintf with the destination size) for all request fields. (EOL: unpatchable.)")

finding("F-16","JavaScript engine: robust to fuzzing (no RCE); deep-nesting DoS only",
 "LOW","Tested (negative for RCE; DoS confirmed)","1ST_READ.BIN JS interpreter @0x8c18b6b0",
 "Contrary to the image decoders, the native JS interpreter is the <b>hardened</b> component. An inline-&lt;script&gt; fuzzing campaign of ~730 mutated scripts (token spam, malformed syntax, huge literals, prototype/type-confusion idioms, AFL byte havoc) produced <b>zero crashes/faults</b> (parse errors cleanly rejected; typical resource use bounded). Only pathological deep nesting/recursion (≈250k-deep) causes a DoS hang (parser/interpreter stack grind), not memory corruption.",
 "1468 requests, 0 faults; deterministic DoS PoC crashes/JSHANG_deepnest.js; writeup crashes/FINDING_js_deepnest_dos.md. (Note: this browser only runs <b>inline</b> scripts, not external &lt;script src&gt;.)",
 "DoS (freeze) only. A JS RCE here, if any, would require grammar-aware generation targeting interpreter type-confusion/GC — out of scope for mutation fuzzing.", None,
 "Bound parser recursion / script resource limits. (EOL: unpatchable.)")

finding("F-17","PersonalJava class loader/verifier: constant_pool_count over-read",
 "LOW","Confirmed live (GDB in-process harness)","Embedded PersonalJava VM class parser; entry 0x8c0f9200 (0xCAFEBABE check @0x8c0f92f4)",
 "The class-file parser trusts the 16-bit <font face='Courier'>constant_pool_count</font> and iterates that many entries without bounding against the actual class size; a large value (0xFFFF, or base+N) over-reads past the buffer → out-of-bounds read / SH-4 fault. The parser also infinite-loops (~90% of malformed classes) — heavily DoS-fragile.",
 "Confirmed with a bespoke GDB-stub in-process fuzz harness (class_fuzz_gdb.py): the parser function was located and re-invoked in-process on mutated classes, classifying RETURN / FAULT@vector / hang. Reachable via the Eden class-load (F-01) and, in principle, &lt;applet&gt; (though applet loading blocks the UI on this build).",
 "DoS-class (OOB read / infinite loop). The over-read is not a controlled write; verifier-level type-confusion RCE would live in the later linker stage (separate harness).", None,
 "Validate constant_pool_count and all CP indices against the class bounds. (EOL: unpatchable.)")

finding("F-18","Additional native parser surface (email POP3/SMTP, SWF/Flash)",
 "INFO","Surface mapped","1ST_READ.BIN: POP3/SMTP client @0x8c181axx, SWF/Flash player @0x8c187xxx",
 "The binary also contains an email client (POP3/SMTP: USER/PASS/RETR/MAIL FROM) and a SWF/Flash player (getURL, SWF_GetVariable, ReadDefineBitsJPEG). The mail client parses server responses (MITM-reachable like Eden, if the user uses email); the Flash player is a large tag-parser/interpreter surface (though &lt;img type=flash&gt; did not drive it on this build). Ruled out by review: no Java deserialization sink on attacker data, no Runtime.exec/ProcessBuilder, and the Eden EventManager reflection dispatch uses only hardcoded class/method names (not attacker-controlled — not a gadget).",
 "String/signature mapping + targeted decompilation/javap of the reachable handlers.",
 "Additional future attack surface; mail requires a mail-server MITM, Flash requires a working embed path.", None,
 "Same memory-safety / input-validation guidance. (EOL: unpatchable.)")

# ---------------- demonstrations ----------------
S.append(PageBreak())
p("5. Exploitation Demonstrations (live, emulated hardware)", H1)
p("<b>5.1 Unauthenticated RCE → browser takeover.</b> The rogue Eden server delivered a Java "
  "service which executed on the console and navigated the browser, with no user action, to an "
  "attacker-controlled page. Captured from the running PlanetWeb browser:")
img(ROOT+"/emu/fc_splash.png", 4.2*inch)
p("<b>5.2 Arbitrary payload — real DOOM in the browser's Java VM.</b> As an impact "
  "demonstration, the RCE delivered (via Jar-Files, F-05) a from-scratch WAD/BSP DOOM engine "
  "(class v45.3, PersonalJava-compatible) that loaded a real IWAD and rendered inside the "
  "browser. Engine output (Freedoom E1M1):")
img(ROOT+"/poc/www/e1m1_doom.png", 4.6*inch)
p("These confirm end-to-end: dead-domain MITM → trusted-but-unsigned code download → "
  "unsandboxed execution → full control of the browser and its Java VM.", SMALL)

# ---------------- native research ----------------
p("6. Native Code-Execution Research (SH-4)", H1)
p("1ST_READ.BIN is an unscrambled SH-4 image loaded at 0x8c010000. Using Capstone and a custom "
  "GDB-remote client against a debug Flycast, the assessment: (a) located and fully decoded the "
  "native <font face='Courier'>sendCommand</font> dispatcher (0x8c04dfa0), recovering every "
  "command→handler address; (b) identified the setRawDeviceID overflow (F-07) and confirmed "
  "it corrupts memory and faults the CPU live; (c) enumerated 28 directly-called function-pointer "
  "globals as candidate control targets.")
p("<b>Weaponization status.</b> The overflow is a fixed-address BSS write. The nearest "
  "corruptible pointer (0x8c29ac28, +0x42) flows into a complex data object rather than a clean "
  "virtual call, and the clean function-pointer globals sit ~900 KB further out (a linear "
  "overflow reaching them destroys too much intervening state). Converting the proven primitive "
  "into reliable arbitrary PC therefore requires either deeper object-graph work or a better-placed "
  "bug; the browser parser surface (F-08) is the more promising route to native execution and the "
  "path subsequently to a homebrew loader / native DOOM.")
code("native sendCommand dispatcher (live-verified):\n"
     "  0x8c04dfa0  cmp/eq #1,r0  ...           ; command switch\n"
     "  code 100 setRawDeviceID -> 0x8c04e0dc -> memcpy(0x8c29abe6, attacker, len)   [NO BOUND CHECK]\n"
     "  code 111 setSecurityFile -> 0x8c04e626 (epilogue: no-op)\n"
     "  overflow corrupts object ptr @0x8c29ac28 (+0x42) -> virtual use -> SH4 exception (confirmed)")

p("6.1 Autonomous in-browser fuzzing campaign", H2)
p("Fuzzing a decoder that lives inside a console browser, in an emulator that reboots on every "
  "crash, is normally throughput-bound. Three pieces removed that bottleneck:")
p("&bull; <b>No-combo crash recovery.</b> A one-line patch to Flycast (dropping the "
  "<font face='Courier'>network.online</font>/storage guards in <font face='Courier'>dc_savestateAllowed</font>) "
  "allows save-states while the modem session is up. A golden save-state of the live, online, "
  "fuzzing browser + <font face='Courier'>AutoLoadState</font> lets a crashed emulator be restored to the "
  "online loop in ~2 seconds with <b>no manual boot/connect sequence</b>.")
p("&bull; <b>Self-driving in-browser loop.</b> The rogue server serves one mutated asset per page "
  "with a cache-proof auto-refresh, so the browser fuzzes itself continuously; a persistent "
  "orchestrator watches the request flow, attributes the culprit on a stall/fault, saves it, and "
  "auto-restores — fully unattended.")
p("&bull; <b>Mutation engine.</b> Structure-aware mutators per format (JPEG markers, PNG IHDR/chunks/IDAT "
  "with CRC fix-up, GIF LZW/dimensions) plus an <b>AFL-derived layer</b> (INTERESTING_8/16/32 boundary "
  "values, havoc, splice, and a corpus that feeds discovered crashers back in), seeded with the project "
  "corpus and Google AFL's image test-cases. AFL's own coverage-guided fork-server is not applicable "
  "(the target is SH-4 guest code in an emulator), but its mutation strategies port directly.")
p("Coverage spanned JPEG, GIF, PNG, plus HTML, gzip Content-Encoding (zlib inflate), JavaScript, and "
  "(via dedicated GDB-stub harnesses) the Java class verifier. The campaign banked many crashing inputs "
  "and produced the deterministic JPEG fault (F-12) and the PNG/GIF overflows (F-13/F-14).")

# ---------------- toolkit ----------------
p("7. Deliverables &amp; Toolkit", H1)
for nm,desc in [
 ("extract_dreamcast.py","GD-ROM/GDI extractor (IP.BIN, 1ST_READ.BIN, full ISO9660 FS)"),
 ("eden_mitm.py","Rogue Eden server; selectable payload chains (splash / jdoom / native / overflow / fuzz)"),
 ("Java payloads","Privileged service JARs (v45.3): splash, real DOOM, native bridge probe, overflow trigger"),
 ("native_recon.py / native_handlers.py","SH-4 dispatcher recovery + handler disassembly (Capstone)"),
 ("native_bssmap.py / fnptr_scan.py","BSS layout + directly-called function-pointer enumeration"),
 ("gdb_rsp.py / gdbstub_probe.py","SH-4 GDB-remote clients (live memory R/W, breakpoints, fault catch)"),
 ("eden_mitm.py (fuzz)","In-browser fuzzer: per-page mutated assets (JPEG/GIF/PNG/SWF/WAV/HTML/gzip/JS) + AFL mutation/havoc/splice/corpus layer"),
 ("fuzz_autorun.py","Self-recovering fuzz orchestrator (stall/fault detect, by-name culprit save, auto-restore)"),
 ("fc_restore.sh / fc_snapshot.py","No-combo crash recovery via patched-Flycast online save-states (~2 s)"),
 ("catch_fault.py","Catches SH-4 exceptions at the VBR vector to read faulting PC/TEA/EXPEVT"),
 ("class_fuzz_gdb.py","In-process PersonalJava class-verifier fuzzer driven over the SH-4 GDB stub"),
 ("Patched Flycast","Source build w/ GDB server + dc_savestateAllowed patch (online save-states for fuzzing)")]:
    p("&bull; <b>%s</b> &mdash; %s" % (nm, desc))
sp(8)
p("8. Disclaimer", H1)
p("All testing was performed by the author against the author's own extracted disc image inside "
  "an emulator, for security research / a hardware-hacking competition (DistrictCon Junkyard). No "
  "third-party systems were accessed. The affected product is end-of-life and unpatchable; "
  "findings are documented for research and educational purposes.", SMALL)

doc = SimpleDocTemplate(OUT, pagesize=LETTER, topMargin=0.7*inch, bottomMargin=0.7*inch,
                        leftMargin=0.8*inch, rightMargin=0.8*inch,
                        title="DistrictCon Junkyard - PlanetWeb v3.0 Security Assessment",
                        author="DistrictCon Junkyard")
def footer(c, d):
    c.setFont("Helvetica", 7); c.setFillColor(colors.grey)
    c.drawString(0.8*inch, 0.4*inch, "PlanetWeb Dreamcast Browser v3.0 — Vulnerability Research Report — CONFIDENTIAL")
    c.drawRightString(7.7*inch, 0.4*inch, "Page %d" % d.page)
doc.build(S, onFirstPage=footer, onLaterPages=footer)
print("wrote", OUT, "%.1f KB" % (os.path.getsize(OUT)/1024))
