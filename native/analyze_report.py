#!/usr/bin/env python3
"""
analyze_report.py -- score the NativeProbe sweep of the PlanetWeb native
sendCommand bridge for exploit promise.

Input: native_report.txt produced by the `native` chain (NativeProbe POSTs it to
eden_mitm's /report). Each line: "<code>\tOK\t<retclass>" | "<code>\tEX\t<exc>"
| "<code>\tSKIP(deny)". Comment lines start with '#'.

Output: a ranked candidate list (undocumented live commands, type-confusion
casts, hang/crash gaps), each with a concrete next probe to run.

  python3 analyze_report.py [native_report.txt]
  python3 analyze_report.py --selftest      # run on a synthetic report
"""
import sys, os, re

# ---- documented Java->native command codes (from decompiled SystemInterface) ----
# code: (name, arg-types or None, notes)
KNOWN = {
    1:  ("sendEdenClientStarted", None, ""),
    3:  ("sendEdenClientFinishedInit", None, ""),
    100:("setRawDeviceID", "byte[]", "WRITES FLASH (denylisted)"),
    101:("getRawDeviceID", None, "->byte[]"),
    102:("getMake", None, "->String"),
    103:("getModel", None, "->String"),
    104:("getOEM", None, "->String"),
    105:("getUserAgent", None, "->String"),
    106:("getBrowserRevision", None, "->String"),
    107:("getDeviceRevision", None, "->String"),
    111:("setSecurityFile", "byte[]", "NATIVE PARSER of attacker bytes (denylisted) - prime target"),
    200:("queryNetworkState", None, "->boolean"),
    203:("networkRequestConnect", None, ""),
    300:("openURL", "String", "native URL handling"),
    301:("goBack", None, ""),
    310:("notifyPendingInstantMessages", None, ""),
    312:("notifyIMReady", None, ""),
    313:("notifyIMDisabled", "String", ""),
    400:("isFeatureEnabled", "String", "->boolean"),
    401:("setFeatureEnabled", "String+Boolean", ""),
    1000:("vmuGetAvailableStorage", None, "->int"),
    1001:("vmuBeginUpdate", "int", ""),
    1002:("vmuEndUpdate", None, ""),
    1003:("vmuPutFile", "String+byte[]", "writes named file to VMU"),
    1004:("vmuDeleteFile", "String", ""),
    1005:("vmuGetFile", "String", "->byte[]"),
    1006:("vmuFreeFile", "String", ""),
}
# native->java (inbound) codes; outbound behavior is undocumented -> interesting
INBOUND = {2:"initFramework", 110:"getSecurityFile", 201:"onConnected",
           202:"onDisconnected", 311:"onActivateIM", 402:"onUserPrefChanged"}

def parse(path):
    rows = {}      # code -> (status, detail)
    notes = []
    last = None
    for ln in open(path):
        ln = ln.rstrip("\n")
        if not ln: continue
        if ln.startswith("#"): notes.append(ln); continue
        p = ln.split("\t")
        try: code = int(p[0])
        except: continue
        status = p[1] if len(p) > 1 else "?"
        detail = p[2] if len(p) > 2 else ""
        rows[code] = (status, detail)
        last = code
    return rows, notes, last

def analyze(rows, last):
    cands = []   # (score, code, tag, reason, nextprobe)
    present = set(rows)
    # 1) gaps in the swept range = codes that produced NO line -> likely hung/crashed
    if present:
        lo, hi = min(present), last if last is not None else max(present)
        for c in range(lo, hi):
            if c not in present and c not in (100, 111):  # deny lines are present anyway
                cands.append((95, c, "HANG/CRASH?",
                    "in swept range but no result line -> probe may have hung or crashed the VM/native side",
                    "re-probe ONLY this code in isolation; if it crashes, it's a candidate primitive"))
        # truncation: last line then nothing -> last code may have hung
        if last is not None and last < hi:
            pass
    for code, (status, detail) in sorted(rows.items()):
        known = code in KNOWN
        if status == "OK" and not known and code not in INBOUND:
            cands.append((90, code, "UNDOCUMENTED",
                "live native command not exposed by SystemInterface (responded OK, ret=%s)" % detail,
                "probe with String and with byte[] args; diff returns; then fuzz oversized byte[]"))
        elif status == "OK" and code in INBOUND:
            cands.append((70, code, "INBOUND-AS-OUTBOUND",
                "native->java code '%s' also accepts outbound calls" % INBOUND[code],
                "inspect handler; feed crafted Object args"))
        elif status == "EX":
            if "ClassCast" in detail:
                kt = KNOWN.get(code, ("?", "?", ""))[1]
                cands.append((85, code, "CASTS-ARG",
                    "native casts the Object arg (ClassCastException) -> type-confusion surface; expects %s" % (kt or "an object"),
                    "send the expected type but malformed (oversized byte[]/long String) to probe the parse"))
            elif "Null" in detail:
                cands.append((60, code, "DEREFS-ARG",
                    "NullPointerException -> handler dereferences the arg",
                    "send a valid object of the likely type; watch for overflow"))
            # generic SystemException = "code rejected / not a command" -> not listed (noise)
    # 2) known high-value parser/memory codes worth manual native RE regardless
    for code, why in ((111,"setSecurityFile: native parser of attacker byte[]"),
                      (1003,"vmuPutFile: attacker filename+bytes -> path/length bugs"),
                      (300,"openURL: native URL/scheme handling"),
                      (100,"setRawDeviceID: attacker bytes -> FLASH (destructive)")):
        st = rows.get(code, ("(denylisted)",""))[0]
        cands.append((80 if code in (111,) else 65, code, "HIGH-VALUE-KNOWN",
            why + "  [sweep status: %s]" % st,
            "RE this handler in 1ST_READ.BIN (native_recon.py); craft malformed arg off-device"))
    # dedupe keep highest score per (code,tag)
    seen = {}
    for sc, code, tag, reason, nxt in cands:
        k = (code, tag)
        if k not in seen or sc > seen[k][0]:
            seen[k] = (sc, code, tag, reason, nxt)
    return sorted(seen.values(), key=lambda x: (-x[0], x[1]))

def report(path):
    rows, notes, last = parse(path)
    print("=== native sendCommand recon analysis:", path, "===")
    for n in notes: print("  " + n)
    ok = [c for c,(s,_) in rows.items() if s=="OK"]
    ex = [c for c,(s,_) in rows.items() if s=="EX"]
    print("  codes: %d reported, %d OK, %d EX; %d documented, %d OK-but-undocumented"
          % (len(rows), len(ok), len(ex), len(KNOWN),
             len([c for c in ok if c not in KNOWN and c not in INBOUND])))
    print()
    print("  %-5s %-6s %-18s %s" % ("SCORE","CODE","CLASS","REASON"))
    print("  " + "-"*92)
    for sc, code, tag, reason, nxt in analyze(rows, last):
        kn = KNOWN.get(code)
        name = (" ("+kn[0]+")") if kn else (" ("+INBOUND[code]+")" if code in INBOUND else "")
        print("  %-5d %-6d %-18s %s%s" % (sc, code, tag, reason, name))
        print("        next: %s" % nxt)

def selftest():
    syn = "/tmp/native_report_synth.txt"
    lines = ["# sendCommand sweep 0..1100 (SYNTHETIC for analyzer self-test)"]
    for c in range(0, 1101):
        if c in (100,111): lines.append("%d\tSKIP(deny)" % c); continue
        if c in KNOWN:
            lines.append("%d\tOK\t%s" % (c, "java.lang.String" if KNOWN[c][1]=="String" else "null"))
        elif c in (108, 109, 250, 500):           # synthetic undocumented live commands
            lines.append("%d\tOK\tnull" % c)
        elif c in (300,313,400,1003,1004,1005):   # casts the arg
            lines.append("%d\tEX\tjava.lang.ClassCastException" % c)
        elif c == 777:                             # synthetic hang -> omit (gap)
            continue
        else:
            lines.append("%d\tEX\tcom.planetweb.eden.client.system.SystemException" % c)
    lines.append("# staged doom.bin bytes=262144")
    open(syn,"w").write("\n".join(lines)+"\n")
    print("[*] wrote synthetic report:", syn, "\n")
    report(syn)

if __name__ == "__main__":
    if "--selftest" in sys.argv: selftest()
    else:
        p = sys.argv[1] if len(sys.argv) > 1 else "native_report.txt"
        if not os.path.exists(p): sys.exit("no report at %s (run --selftest for a demo)" % p)
        report(p)
