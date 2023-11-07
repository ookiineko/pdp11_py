import sys
import threading
import traceback

from cons import *
from rk05 import *
from disasm import *

FLAGN = 8
FLAGZ = 4
FLAGV = 2
FLAGC = 1

pr = False
R = [0, 0, 0, 0, 0, 0, 0, 0] # registers
KSP = USP = None # kernel and user stack pointer
PS = None # processor status
curPC = None # address of current instruction
lastPCs = []
inst = None # current instruction
memory = [None for _ in range(128*1024)] # word addressing
import rk05
import disasm as _disasm
rk05.memory = memory
_disasm.memory = memory
tim1 = tim2 = None
ips = None
SR0 = SR2 = None
curuser = prevuser = None
LKS = clkcounter = None
waiting = False
interrupts = []

pages = [None for _ in range(16)]

# traps
INTBUS, INTINVAL, INTDEBUG, INTIOT, INTTTYIN, INTTTYOUT, INTFAULT, INTCLOCK, INTRK = 0o004, 0o010, 0o014, 0o020, 0o060, 0o064, 0o250, 0o100, 0o220

import cons
cons.INTTTYIN = INTTTYIN
cons.INTTTYOUT = INTTTYOUT
rk05.INTRK = INTRK

bootrom = (
    0o042113,                         # "KD"
    0o012706, 0o2000,                 # MOV #boot_start, SP
    0o012700, 0o000000,               # MOV #unit, R0        ; unit number
    0o010003,                         # MOV R0, R3
    0o000303,                         # SWAB R3
    0o006303,                         # ASL R3
    0o006303,                         # ASL R3
    0o006303,                         # ASL R3
    0o006303,                         # ASL R3
    0o006303,                         # ASL R3
    0o012701, 0o177412,               # MOV #RKDA, R1        ; csr
    0o010311,                         # MOV R3, (R1)         ; load da
    0o005041,                         # CLR -(R1)            ; clear ba
    0o012741, 0o177000,               # MOV #-256.*2, -(R1)  ; load wc
    0o012741, 0o000005,               # MOV #READ+GO, -(R1)  ; read & go
    0o005002,                         # CLR R2
    0o005003,                         # CLR R3
    0o012704, 0o2020,                 # MOV #START+20, R4
    0o005005,                         # CLR R5
    0o105711,                         # TSTB (R1)
    0o100376,                         # BPL .-2
    0o105011,                         # CLRB (R1)
    0o005007                          # CLR PC
    )

def xor(a,b):
    return (a or b) and not (a and b)

def switchmode(newm):
    global prevuser, curuser, USP, KSP, PS
    prevuser = curuser
    curuser = newm
    if prevuser: USP = R[6]
    else: KSP = R[6]
    if curuser: R[6] = USP
    else: R[6] = KSP
    PS &= 0o007777
    if curuser: PS |= (1<<15)|(1<<14)
    if prevuser: PS |= (1<<13)|(1<<12)

def physread16(a):
    if a & 1: raise Trap(INTBUS, "read from odd address " + ostr(a,6))
    if a < 0o760000: return memory[a>>1]
    if a == 0o777546: return LKS
    if a == 0o777570: return 0o173030
    if a == 0o777572: return SR0
    if a == 0o777576: return SR2
    if a == 0o777776: return PS
    if (a & 0o777770) == 0o777560: return consread16(a)
    if (a & 0o777760) == 0o777400: return rkread16(a)
    if (a & 0o777600) == 0o772200 or (a & 0o777600) == 0o777600: return mmuread16(a)
    if a == 0o776000: panic("lolwut")
    raise Trap(INTBUS, "read from invalid address " + ostr(a,6))

def physread8(a):
    val = physread16(a & ~1)
    if (a & 1): return val >> 8
    return val & 0xFF

def physwrite8(a,v):
    if a < 0o760000:
        if a & 1:
            memory[a>>1] &= 0xFF
            memory[a>>1] |= (v & 0xFF) << 8
        else:
            memory[a>>1] &= 0xFF00
            memory[a>>1] |= v & 0xFF
    else:
        if a & 1:
            physwrite16(a&~1, (physread16(a) & 0xFF) | ((v & 0xFF) << 8))
        else:
            physwrite16(a&~1, (physread16(a) & 0xFF00) | (v & 0xFF))

def physwrite16(a,v):
    global PS, LKS, SR0, prevuser
    if a % 1: raise Trap(INTBUS, "write to odd address " + ostr(a,6))
    if a < 0o760000: memory[a>>1] = v
    elif a == 0o777776:
        match v >> 14:
            case 0: switchmode(False)
            case 3: switchmode(True)
            case _: panic("invalid mode")
        match (v >> 12) & 3:
            case 0: prevuser = False
            case 3: prevuser = True
            case _: panic("invalid mode")
        PS = v
    elif a == 0o777546: LKS = v
    elif a == 0o777572: SR0 = v
    elif (a & 0o777770) == 0o777560: conswrite16(a,v)
    elif (a & 0o777700) == 0o777400: rkwrite16(a,v)
    elif (a & 0o777600) == 0o772200 or (a & 0o777600) == 0o777600: mmuwrite16(a,v)
    else: raise Trap(INTBUS, "write to invalid address " + ostr(a,6))

def decode(a,w,m):
    global SR0, SR2
    if not SR0 & 1:
        if a >= 0o170000: a += 0o600000
        return a
    user = 8 if m else 0
    p = pages[(a >> 13) + user]
    if w and not p["write"]:
        SR0 = (1<<13) | 1
        SR0 |= (a >> 12) & ~1
        if user: SR0 |= (1<<5)|(1<<6)
        SR2 = curPC
        raise Trap(INTFAULT, "write to read-only page " + ostr(a,6))
    if not p["read"]:
        SR0 = (1<<15) | 1
        SR0 |= (a >> 12) & ~1
        if user: SR0 |= (1<<5)|(1<<6)
        SR2 = curPC
        raise Trap(INTFAULT, "read from no-access page " + ostr(a,6))
    block = (a >> 6) & 0o177
    disp = a & 0o77
    if (block < p["len"]) if p["ed"] else (block > p["len"]):
        SR0 = (1<<14) | 1
        SR0 |= (a >> 12) & ~1
        if user: SR0 |= (1<<5)|(1<<6)
        SR2 = curPC
        raise Trap(INTFAULT, "page length exceeded, address " + ostr(a,6) + " (block " + ostr(block,3) + ") is beyond length " + ostr(p["len"],3))
    if w: p["pdr"] |= 1<<6
    return ((block + p["addr"]) << 6) + disp

def createpage(par,pdr):
    return {
        "par" : par,
        "pdr" : pdr,
        "addr" : par & 0o7777,
        "len" : (pdr >> 8) & 0x7F,
        "read" : (pdr & 2) == 2,
        "write" : (pdr & 6) == 6,
        "ed" : (pdr & 8) == 8
    }

def mmuread16(a):
    i = (a & 0o17)>>1
    if (a >= 0o772300) and (a < 0o772320):
        return pages[i]["pdr"]
    if (a >= 0o772340) and (a < 0o772360):
        return pages[i]["par"]
    if (a >= 0o777600) and (a < 0o777620):
        return pages[i+8]["pdr"]
    if (a >= 0o777640) and (a < 0o777660):
        return pages[i+8]["par"]
    raise Trap(INTBUS, "invalid read from " + ostr(a,6))

def mmuwrite16(a, v):
    i = (a & 0o17)>>1
    if (a >= 0o772300) and (a < 0o772320):
        pages[i] = createpage(pages[i]["par"], v)
        return
    if (a >= 0o772340) and (a < 0o772360):
        pages[i] = createpage(v, pages[i]["pdr"])
        return
    if (a >= 0o777600) and (a < 0o777620):
        pages[i+8] = createpage(pages[i+8]["par"], v)
        return
    if (a >= 0o777640) and (a < 0o777660):
        pages[i+8] = createpage(v, pages[i+8]["pdr"])
        return
    raise Trap(INTBUS, "write to invalid address " + ostr(a,6))

def read8(a):
    return physread8(decode(a, False, curuser))

def read16(a, *args):
    return physread16(decode(a, False, curuser))

def write8(a, v):
    return physwrite8(decode(a, True, curuser),v)

def write16(a, v):
    return physwrite16(decode(a, True, curuser),v)

def fetch16():
    val = read16(R[7])
    R[7] += 2
    return val

def push(v):
    R[6] -= 2
    write16(R[6], v)

def pop(v=None):
    val = read16(R[6], v)
    R[6] += 2
    return val

def ostr(z,n=None):
    if n is None: n = 6
    val = oct(z)[2:]
    while len(val) < n:
        val = "0"+val
    return val

cons.ostr = ostr

def cleardebug():
    print('\033[2J\033[H', file=sys.stderr, end='', flush=True)

def writedebug(msg):
    print(msg, file=sys.stderr, end='', flush=True)

def printstate():
    writedebug(
        "R0 " + ostr(R[0],6) + " " +
        "R1 " + ostr(R[1],6) + " " +
        "R2 " + ostr(R[2],6) + " " +
        "R3 " + ostr(R[3],6) + " " +
        "R4 " + ostr(R[4],6) + " " +
        "R5 " + ostr(R[5],6) + " " +
        "R6 " + ostr(R[6],6) + " " +
        "R7 " + ostr(R[7],6)
    + "\n[")
    writedebug("u") if prevuser else writedebug("k")
    writedebug("U") if curuser else writedebug("K")
    writedebug("N") if PS & FLAGN else writedebug(" ")
    writedebug("Z") if PS & FLAGZ else writedebug(" ")
    writedebug("V") if PS & FLAGV else writedebug(" ")
    writedebug("C") if PS & FLAGC else writedebug(" ")
    writedebug("]  instr " + ostr(curPC,6) + ": " + ostr(instr,6)+"   ")
    try:
        writedebug(disasm(decode(curPC,False,curuser)))
    except:
        pass
    writedebug("\n\n")

def panic(msg):
    writedebug(msg+"\n")
    printstate()
    stop()
    raise Exception(msg)

rk05.panic = panic
cons.panic = panic

class Trap(Exception):
    def __init__(self, num, msg):
        self.num = num
        self.msg = msg

def interrupt(vec, pri):
    if vec & 1: panic("Thou darst calling interrupt() with an odd vector number?")
    i = 0
    for i in range(len(interrupts)):
        if interrupts[i]["pri"] < pri:
            break
    for i in range(i, len(interrupts)):
        if interrupts[i]["vec"] >= vec:
            break
    interrupts.insert(i, {"vec": vec, "pri": pri})

cons.interrupt = interrupt
rk05.interrupt = interrupt

def handleinterrupt(vec):
    global prev, PS, waiting
    try:
        prev = PS
        switchmode(False)
        push(prev)
        push(R[7])
    except Trap as e:
        trapat(e.num, e.msg)
    R[7] = memory[vec>>1]
    PS = memory[(vec>>1)+1]
    if prevuser: PS |= (1<<13)|(1<<12)
    waiting = False

def trapat(vec, msg):
    global prev, PS, waiting
    if vec & 1: panic("Thou darst calling trapat() with an odd vector number?")
    writedebug("trap " + ostr(vec) + " occured: " + msg + "\n")
    printstate()
    try:
        prev = PS
        switchmode(False)
        push(prev)
        push(R[7])
    except Trap as e:
        writedebug("red stack trap!\n")
        memory[0] = R[7]
        memory[1] = prev
        vec = 4
    R[7] = memory[vec>>1]
    PS = memory[(vec>>1)+1]
    if prevuser: PS |= (1<<13)|(1<<12)
    waiting = False

def aget(v, l):
    if (v & 7) >= 6 or (v & 0o10): l = 2
    if (v & 0o70) == 0o00:
        return -(v + 1)
    match v & 0o60:
        case 0o00:
            v &= 7
            addr = R[v & 7]
        case 0o20:
            addr = R[v & 7]
            R[v & 7] += l
        case 0o40:
            R[v & 7] -= l
            addr = R[v & 7]
        case 0o60:
            addr = fetch16()
            addr += R[v & 7]
    addr &= 0xFFFF
    if v & 0o10:
        addr = read16(addr)
    return addr

def memread(a, l):
    if a < 0:
        if l == 2:
            return R[-(a + 1)]
        else:
            return R[-(a + 1)] & 0xFF
    if l == 2:
        return read16(a)
    return read8(a)

def memwrite(a, l, v):
    if a < 0:
        if l == 2:
            R[-(a + 1)] = v
        else:
            R[-(a + 1)] &= 0xFF00
            R[-(a + 1)] |= v
    elif l == 2:
        write16(a, v)
    else:
        write8(a, v)

def branch(o):
    if o & 0x80:
        o = -(((~o)+1)&0xFF)
    o <<= 1
    R[7] += o

def step():
    global ips, waiting, curPC, lastPCs, instr, PS, KSP, USP, LKS
    ips+=1
    if waiting: return
    curPC = R[7]
    ia = decode(R[7], False, curuser)
    R[7] += 2
    lastPCs = lastPCs[:100]
    lastPCs.insert(0, ia)
    instr = physread16(ia)
    d = instr & 0o77
    s = (instr & 0o7700) >> 6
    l = 2 - (instr >> 15)
    o = instr & 0xFF
    if l == 2:
        max = 0xFFFF
        maxp = 0x7FFF
        msb = 0x8000
    else:
        max = 0xFF
        maxp = 0x7F
        msb = 0x80
    match instr & 0o070000:
        case 0o010000: # MOV
            sa = aget(s, l); val = memread(sa, l)
            da = aget(d, l)
            PS &= 0xFFF1
            if val is not None and val & msb: PS |= FLAGN
            if val == 0: PS |= FLAGZ
            if da < 0 and l == 1:
                l = 2
                if val & msb: val |= 0xFF00
            memwrite(da, l, val)
            return
        case 0o020000: # CMP
            sa = aget(s, l); val1 = memread(sa, l)
            da = aget(d, l); val2 = memread(da, l)
            val = (val1 - val2) & max
            PS &= 0xFFF0
            if val == 0: PS |= FLAGZ
            if val & msb: PS |= FLAGN
            if ((val1 ^ val2) & msb) and not (val2 ^ val) & msb: PS |= FLAGV
            if val1 < val2: PS |= FLAGC
            return
        case 0o030000: # BIT
            sa = aget(s, l); val1 = memread(sa, l)
            da = aget(d, l); val2 = memread(da, l)
            val = val1 & val2
            PS &= 0xFFF1
            if val == 0: PS |= FLAGZ
            if val & msb: PS |= FLAGN
            return
        case 0o040000: # BIC
            sa = aget(s, l); val1 = memread(sa, l)
            da = aget(d, l); val2 = memread(da, l)
            val = (max ^ val1) & val2
            PS &= 0xFFF1
            if val == 0: PS |= FLAGZ
            if val & msb: PS |= FLAGN
            memwrite(da, l, val)
            return
        case 0o050000: # BIS
            sa = aget(s, l); val1 = memread(sa, l)
            da = aget(d, l); val2 = memread(da, l)
            val = val1 | val2
            PS &= 0xFFF1
            if val == 0: PS |= FLAGZ
            if val & msb: PS |= FLAGN
            memwrite(da, l, val)
            return
    match instr & 0o170000:
        case 0o060000: # ADD
            sa = aget(s, 2); val1 = memread(sa, 2)
            da = aget(d, 2); val2 = memread(da, 2)
            val = (val1 + val2) & 0xFFFF
            PS &= 0xFFF0
            if val == 0: PS |= FLAGZ
            if val & 0x8000: PS |= FLAGN
            if not (val1 ^ val2) & 0x8000 and ((val2 ^ val) & 0x8000): PS |= FLAGV
            if val1 + val2 >= 0xFFFF: PS |= FLAGC
            memwrite(da, 2, val)
            return
        case 0o160000: # SUB
            sa = aget(s, 2); val1 = memread(sa, 2)
            da = aget(d, 2); val2 = memread(da, 2)
            val = (val2 - val1) & 0xFFFF
            PS &= 0xFFF0
            if val == 0: PS |= FLAGZ
            if val & 0x8000: PS |= FLAGN
            if ((val1 ^ val2) & 0x8000) and not (val2 ^ val) & 0x8000: PS |= FLAGV
            if val1 > val2: PS |= FLAGC
            memwrite(da, 2, val)
            return
    match instr & 0o177000:
        case 0o004000: # JSR
            val = aget(d, l)
            if val < 0: pass
            else:
                push(R[s & 7])
                R[s & 7] = R[7]
                R[7] = val
                return
        case 0o070000: # MUL
            val1 = R[s & 7]
            if val1 & 0x8000: val1 = -((0xFFFF^val1)+1)
            da = aget(d, l); val2 = memread(da, 2)
            if val2 & 0x8000: val2 = -((0xFFFF^val2)+1)
            val = val1 * val2
            R[s & 7] = (val & 0xFFFF0000) >> 16
            R[(s & 7)|1] = val & 0xFFFF
            PS &= 0xFFF0
            if val & 0x80000000: PS |= FLAGN
            if (val & 0xFFFFFFFF) == 0: PS |= FLAGZ
            if val < (1<<15) or val >= ((1<<15)-1): PS |= FLAGC
            return
        case 0o071000: # DIV
            val1 = (R[s & 7] << 16) | R[(s & 7) | 1]
            da = aget(d, l); val2 = memread(da, 2)
            PS &= 0xFFF0
            if val2 == 0:
                PS |= FLAGC
                return
            if (val1 / val2) >= 0x10000:
                PS |= FLAGV
                return
            R[s & 7] = (val1 // val2) & 0xFFFF
            R[(s & 7) | 1] = (val1 % val2) & 0xFFFF
            if R[s & 7] == 0: PS |= FLAGZ
            if R[s & 7] & 0o100000: PS |= FLAGN
            if val1 == 0: PS |= FLAGV
            return
        case 0o072000: # ASH
            val1 = R[s & 7]
            da = aget(d, 2); val2 = memread(da, 2) & 0o77
            PS &= 0xFFF0
            if val2 & 0o40:
                val2 = (0o77 ^ val2) + 1
                if val1 & 0o100000:
                    val = 0xFFFF ^ (0xFFFF >> val2)
                    val |= val1 >> val2
                else:
                    val = val1 >> val2
                if val1 & (1 << (val2 - 1)): PS |= FLAGC
            else:
                val = (val1 << val2) & 0xFFFF
                if val1 & (1 << (16 - val2)): PS |= FLAGC
            R[s & 7] = val
            if val == 0: PS |= FLAGZ
            if val & 0o100000: PS |= FLAGN
            if xor(val & 0o100000, val1 & 0o100000): PS |= FLAGV
            return
        case 0o073000: # ASHC
            val1 = (R[s & 7] << 16) | R[(s & 7) | 1]
            da = aget(d, 2); val2 = memread(da, 2) & 0o77
            PS &= 0xFFF0
            if val2 & 0o40:
                val2 = (0o77 ^ val2) + 1
                if val1 & 0x80000000:
                    val = 0xFFFFFFFF ^ (0xFFFFFFFF >> val2)
                    val |= val1 >> val2
                else:
                    val = val1 >> val2
                if val1 & (1 << (val2 - 1)): PS |= FLAGC
            else:
                val = (val1 << val2) & 0xFFFFFFFF
                if val1 & (1 << (32 - val2)): PS |= FLAGC
            R[s & 7] = (val >> 16) & 0xFFFF
            R[(s & 7)|1] = val & 0xFFFF
            if val == 0: PS |= FLAGZ
            if val & 0x80000000: PS |= FLAGN
            if xor(val & 0x80000000, val1 & 0x80000000): PS |= FLAGV
            return
        case 0o074000: # XOR
            val1 = R[s & 7]
            da = aget(d, 2); val2 = memread(da, 2)
            val = val1 ^ val2
            PS &= 0xFFF1
            if val == 0: PS |= FLAGZ
            if val & 0x8000: PS |= FLAGZ
            memwrite(da, 2, val)
            return
        case 0o077000: # SOB
            R[s & 7] -= 1
            if R[s & 7]:
                o &= 0o77
                o <<= 1
                R[7] -= o
            return
    match instr & 0o077700:
        case 0o005000: # CLR
            PS &= 0xFFF0
            PS |= FLAGZ
            da = aget(d, l)
            memwrite(da, l, 0)
            return
        case 0o005100: # COM
            da = aget(d, l)
            val = memread(da, l) ^ max
            PS &= 0xFFF0; PS |= FLAGC
            if val & msb: PS |= FLAGN
            if val == 0: PS |= FLAGZ
            memwrite(da, l, val)
            return
        case 0o005200: # INC
            da = aget(d, l)
            val = (memread(da, l) + 1) & max
            PS &= 0xFFF1
            if val & msb: PS |= FLAGN | FLAGV
            if val == 0: PS |= FLAGZ
            memwrite(da, l, val)
            return
        case 0o005300: # DEC
            da = aget(d, l)
            val = (memread(da, l) - 1) & max
            PS &= 0xFFF1
            if val & msb: PS |= FLAGN
            if val == maxp: PS |= FLAGV
            if val == 0: PS |= FLAGZ
            memwrite(da, l, val)
            return
        case 0o005400: # NEG
            da = aget(d, l)
            val = (-memread(da, l)) & max
            PS &= 0xFFF0
            if val & msb: PS |= FLAGN
            if val == 0: PS |= FLAGZ
            else: PS |= FLAGC
            if val == 0x8000: PS |= FLAGV
            memwrite(da, l, val)
            return
        case 0o005500: # ADC
            da = aget(d, l)
            val = memread(da, l)
            if PS & FLAGC:
                PS &= 0xFFF0
                if (val + 1) & msb: PS |= FLAGN
                if val == max: PS |= FLAGZ
                if val == 0o077777: PS |= FLAGV
                if val == 0o177777: PS |= FLAGC
                memwrite(da, l, (val+1) & max)
            else:
                PS &= 0xFFF0
                if val & msb: PS |= FLAGN
                if val == 0: PS |= FLAGZ
            return
        case 0o005600: # SBC
            da = aget(d, l)
            val = memread(da, l)
            if PS & FLAGC:
                PS &= 0xFFF0
                if (val - 1) & msb: PS |= FLAGN
                if val == 1: PS |= FLAGZ
                if val: PS |= FLAGC
                if val == 0o100000: PS |= FLAGV
                memwrite(da, l, (val-1) & max)
            else:
                PS &= 0xFFF0
                if val & msb: PS |= FLAGN
                if val == 0: PS |= FLAGZ
                if val == 0o100000: PS |= FLAGV
                PS |= FLAGC
            return
        case 0o005700: # TST
            da = aget(d, l)
            val = memread(da, l)
            PS &= 0xFFF0
            if val & msb: PS |= FLAGN
            if val == 0: PS |= FLAGZ
            return
        case 0o006000: # ROR
            da = aget(d, l)
            val = memread(da, l)
            if PS & FLAGC: val |= max+1
            PS &= 0xFFF0
            if val & 1: PS |= FLAGC
            if val & (max+1): PS |= FLAGN
            if not (val & max): PS |= FLAGZ
            if xor(val & 1, val & (max+1)): PS |= FLAGV
            val >>= 1
            memwrite(da, l, val)
            return
        case 0o006100: # ROL
            da = aget(d, l)
            val = memread(da, l) << 1
            if PS & FLAGC: val |= 1
            PS &= 0xFFF0
            if val & (max+1): PS |= FLAGC
            if val & msb: PS |= FLAGN
            if not (val & max): PS |= FLAGZ
            if (val ^ (val >> 1)) & msb: PS |= FLAGV
            val &= max
            memwrite(da, l, val)
            return
        case 0o006200: # ASR
            da = aget(d, l)
            val = memread(da, l)
            PS &= 0xFFF0
            if val & 1: PS |= FLAGC
            if val & msb: PS |= FLAGN
            if xor(val & msb, val & 1): PS |= FLAGV
            val = (val & msb) | (val >> 1)
            if val == 0: PS |= FLAGZ
            memwrite(da, l, val)
            return
        case 0o006300: # ASL
            da = aget(d, l)
            val = memread(da, l)
            PS &= 0xFFF0
            if val & msb: PS |= FLAGC
            if val & (msb >> 1): PS |= FLAGN
            if (val ^ (val << 1)) & msb: PS |= FLAGV
            val = (val << 1) & max
            if val == 0: PS |= FLAGZ
            memwrite(da, l, val)
            return
        case 0o006700: # SXT
            da = aget(d, l)
            if PS & FLAGN:
                memwrite(da, l, max)
            else:
                PS |= FLAGZ
                memwrite(da, l, 0)
            return
    match instr & 0o177700:
        case 0o000100: # JMP
            val = aget(d, 2)
            if val < 0:
                pass
            else:
                R[7] = val
                return
        case 0o000300: # SWAB
            da = aget(d, l)
            val = memread(da, l)
            val = ((val >> 8) | (val << 8)) & 0xFFFF
            PS &= 0xFFF0
            if (val & 0xFF) == 0: PS |= FLAGZ
            if val & 0x80: PS |= FLAGN
            memwrite(da, l, val)
            return
        case 0o006400: # MARK
            R[6] = R[7] + (instr & 0o77) << 1
            R[7] = R[5]
            R[5] = pop()
        case 0o006500: # MFPI
            da = aget(d, 2)
            if da == -7:
                val =  R[6] if (curuser == prevuser) else (USP if prevuser else KSP)
            elif da < 0:
                panic("invalid MFPI instruction")
            else:
                val = physread16(decode(da, False, prevuser))
            push(val)
            PS &= 0xFFF0; PS |= FLAGC
            if val == 0: PS |= FLAGZ
            if val & 0x8000: PS |= FLAGN
            return
        case 0o006600: # MTPI
            da = aget(d, 2)
            val = pop()
            if da == -7:
                if curuser == prevuser: R[6] = val
                elif prevuser: USP = val
                else: KSP = val
            elif da < 0:
                panic("invalid MTPI instrution")
            else:
                sa = decode(da, True, prevuser)
                physwrite16(sa, val)
            PS &= 0xFFF0; PS |= FLAGC
            if val == 0: PS |= FLAGZ
            if val & 0x8000: PS |= FLAGN
            return
    if (instr & 0o177770) == 0o000200:
        R[7] = R[d & 7]
        R[d & 7] = pop()
        return
    match instr & 0o177400:
        case 0o000400: branch(o); return
        case 0o001000:
            if not (PS & FLAGZ): branch(o)
            return
        case 0o001400:
            if PS & FLAGZ: branch(o)
            return
        case 0o002000:
            if not xor(PS & FLAGN, PS & FLAGV): branch(o)
            return
        case 0o002400:
            if xor(PS & FLAGN, PS & FLAGV): branch(o)
            return
        case 0o003000:
            if not xor(PS & FLAGN, PS & FLAGV) and not (PS & FLAGZ): branch(o)
            return
        case 0o003400:
            if xor(PS & FLAGN, PS & FLAGV) or (PS & FLAGZ): branch(o)
            return
        case 0o100000:
            if not (PS & FLAGN): branch(o)
            return
        case 0o100400:
            if PS & FLAGN: branch(o)
            return
        case 0o101000:
            if not (PS & FLAGC) and not (PS & FLAGZ): branch(o)
            return
        case 0o101400:
            if (PS & FLAGC) or (PS & FLAGZ): branch(o)
            return
        case 0o102000:
            if not (PS & FLAGV): branch(o)
            return
        case 0o102400:
            if PS & FLAGV: branch(o)
            return
        case 0o103000:
            if not (PS & FLAGC): branch(o)
            return
        case 0o103400:
            if PS & FLAGC: branch(o)
            return
    if (instr & 0o177000) == 0o104000 or instr == 3 or instr == 4: # EMT TRAP IOT BPT
        if (instr & 0o177400) == 0o104000: vec = 0o30
        elif (instr & 0o177400) == 0o104400: vec = 0o34
        elif instr == 3: vec = 0o14
        else: vec = 0o20
        prev = PS
        switchmode(False)
        push(prev)
        push(R[7])
        R[7] = memory[vec>>1]
        PS = memory[(vec>>1)+1]
        if prevuser: PS |= (1<<13)|(1<<12)
        return
    if (instr & 0o177740) == 0o240: # CL?, SE?
        if instr & 0o20:
            PS |= instr & 0o17
        else:
            PS &= ~(instr & 0o17)
        return
    match instr:
        case 0o000000: # HALT
            if curuser:
                pass
            else:
                writedebug("HALT\n")
                printstate()
                stop()
                return
        case 0o000001: # WAIT
#           stop()
#           threading.Timer(0.02, exec, ('''\
#global LKS
#import traceback
#try:
#    LKS |= 0x80; interrupt(INTCLOCK, 6); run();
#except:
#    traceback.print_exc()
#''', globals(), locals())); # FIXME, really
            if curuser: pass
            else:
                waiting = True
                return
        case 0o000002 | 0o000006: # RTI | RTT
            R[7] = pop()
            val = pop()
            if curuser:
                val &= 0o47
                val |= PS & 0o177730
            physwrite16(0o777776, val)
            return
        case 0o000005: # RESET
            if curuser: return
            clearterminal()
            rkreset()
            return
        case 0o170011: # SETD ; not needed by UNIX, but used; therefore ignored
            return
    raise Trap(INTINVAL, "invalid instruction")

def reset():
    global PS, KSP, USP, curuser, prevuser, SR0, curPC, instr, ips, LKS, clkcounter, waiting
    for i in range(7): R[i] = 0
    PS = 0
    KSP = 0
    USP = 0
    curuser = False
    prevuser = False
    SR0 = 0
    curPC = 0
    instr = 0
    ips = 0
    LKS = 1<<7
    for i in range(len(memory)): memory[i] = 0
    for i in range(len(bootrom)): memory[0o1000+i] = bootrom[i]
    for i in range(16): pages[i] = createpage(0, 0)
    R[7] = 0o2002
    cleardebug()
    clearterminal()
    rkreset()
    clkcounter = 0
    waiting = False

def nsteps(n):
    global clkcounter, LKS
    while n:
        n-=1
        try:
            step()
            if len(interrupts) and interrupts[0]["pri"] >= ((PS >> 5) & 7):
                handleinterrupt(interrupts[0]["vec"])
                interrupts.pop(0)
            clkcounter+=1
            if clkcounter >= 40000:
                clkcounter = 0
                LKS |= (1<<7)
                if LKS & (1<<6): interrupt(INTCLOCK, 6)
        except Trap as e:
            trapat(e.num, e.msg)
        if pr:
            printstate()

def run():
    global tim1
    def inner():
        if tim1:
                nsteps(4000)
                g = globals()
                g["inner"] = inner
                threading.Timer(0.001, exec, ('''\
import traceback
try:
    inner()
except:
    traceback.print_exc()
''', g, locals())).start()
    try:
        if not tim1:
            tim1 = True
            inner()
    except NameError:
        pass

def stop():
    global tim1
    tim1 = False
