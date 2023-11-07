import threading
import os
import os.path
import traceback

RKDS = RKER = RKCS = RKWC = RKBA = drive = sector = surface = cylinder = rkimg = None

imglen = 2077696

RKOVR, RKNXD, RKNXC, RKNXS = (1<<14), (1<<7), (1<<6), (1<<5)

def rkread16(a):
    match a:
        case 0o777400: return RKDS
        case 0o777402: return RKER
        case 0o777404: return RKCS | ((RKBA & 0x30000) >> 12)
        case 0o777406: return RKWC
        case 0o777410: return RKBA & 0xFFFF
        case 0o777412: return (sector) | (surface << 4) or (cylinder << 5) | (drive << 13)
    panic("invalid read")

def rknotready():
    global RKDS, RKCS
    RKDS &= ~(1<<6)
    RKCS &= ~(1<<7)

def rkready():
    global RKDS, RKCS
    RKDS |= 1<<6
    RKCS |= 1<<7

def rkerror(code):
    global RKER, RKCS
    msg = None
    rkready()
    RKER |= code
    RKCS |= (1<<15) | (1<<14)
    match code:
        case int(RKOVR): msg = "operation overflowed the disk"
        case int(RKNXD): msg = "invalid disk accessed"
        case int(RKNXC): msg = "invalid cylinder accessed"
        case int(RKNXS): msg = "invalid sector accessed"
    panic(msg)

def rkrwsec(t):
    global RKBA, RKWC, sector, surface, cylinder
    if drive != 0: rkerror(RKNXD)
    if cylinder > 0o312: rkerror(RKNXC)
    if sector > 0o13: rkerror(RKNXS)
    pos = (cylinder * 24 + surface * 12 + sector) * 512
    for _ in range(256):
        if not RKWC:
            break
        if t:
            val = memory[RKBA >> 1]
            rkdisk[pos] = val & 0xFF
            rkdisk[pos+1] = (val >> 8) & 0xFF
        else:
            memory[RKBA >> 1] = rkdisk[pos] | (rkdisk[pos+1] << 8)
        RKBA += 2
        pos += 2
        RKWC = (RKWC + 1) & 0xFFFF
    sector+=1
    if sector > 0o13:
        sector = 0
        surface+=1
        if surface > 1:
            surface = 0
            cylinder+=1
            if cylinder > 0o312:
                rkerror(RKOVR)
    if RKWC:
        g = globals()
        g["rkrwsec"] = rkrwsec
        threading.Timer(0.003, exec, (f'''\
import traceback
try:
    rkrwsec({t})
except:
    traceback.print_exc()
''', g, locals())).start()
    else:
        rkready()
        if RKCS & (1<<6): interrupt(INTRK, 5)

def rkgo():
    match (RKCS & 0o17) >> 1:
        case 0: rkreset()
        case 1: rknotready(); threading.Timer(0.003, exec, ('''\
import traceback
try:
    rkrwsec(True)
except:
    traceback.print_exc()
''', globals(), locals())).start()
        case 2: rknotready(); threading.Timer(0.003, exec, ('''\
import traceback
try:
    rkrwsec(False)
except:
    traceback.print_exc()
''', globals(), locals())).start()
        case _: panic("unimplemented RK05 operation " + str((RKCS & 0o17) >> 1))

def rkwrite16(a,v):
    global RKBA, RKCS, RKWC, drive, cylinder, surface, sector
    match a:
        case 0o777400: pass
        case 0o777402: pass
        case 0o777404:
            RKBA = (RKBA & 0xFFFF) | ((v & 0o60) << 12)
            v &= 0o17517 # writable bits
            RKCS &= ~0o17517
            RKCS |= v & ~1 # don't set GO bit
            if v & 1: rkgo()
        case 0o777406: RKWC = v
        case 0o777410: RKBA = (RKBA & 0x30000) | v
        case 0o777412:
            drive = v >> 13
            cylinder = (v >> 5) & 0o377
            surface = (v >> 4) & 1
            sector = v & 15
        case _:
            panic("invalid write")

def rkreset():
    global RKDS, RKER, RKCS, RKWC, RKBA, RKDB
    RKDS = (1 << 11) | (1 << 7) | (1 << 6)
    RKER = 0
    RKCS = 1 << 7
    RKWC = 0
    RKBA = 0
    RKDB = 0

def rkinit():
    global rkdisk
    if not os.access('rk0', os.R_OK) or not os.path.isfile('rk0'): panic("could not load disk image")
    with open('rk0', 'rb') as f:
        buf = f.read()
    if len(buf) != imglen: panic("file too short, got " + str(len(buf)) + ", expected " + str(imglen))
    rkdisk = bytearray(buf)
