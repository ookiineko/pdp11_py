import threading
import traceback

TKS = TPS = keybuf = 0

def clearterminal():
    global TKS, TPS
    print('\033[2J\033[H', end='', flush=True)
    TKS = 0
    TPS = 1<<7

def writeterminal(msg):
    print(msg, end='', flush=True)

def addchar(c):
    global TKS, keybuf
    TKS |= 0x80
    keybuf = c
    if TKS & (1<<6): interrupt(INTTTYIN, 4)

def specialchar(c):
    global keybuf, TKS
    match c:
        case 42: keybuf = 4
        case 19: keybuf = 0o32
        case 46: keybuf = 127
        case _:
            return
    TKS |= 0x80
    if TKS & (1<<6): interrupt(INTTTYIN, 4)

def getchar():
    global TKS
    if TKS & 0x80:
        TKS &= 0xff7e
        return keybuf
    return 0

def consread16(a):
    match a:
        case 0o777560: return TKS
        case 0o777562: return getchar()
        case 0o777564: return TPS
        case 0o777566: return 0
    panic("read from invalid address " + ostr(a,6))

def conswrite16(a,v):
    global TKS, TPS
    match a:
        case 0o777560:
            if v & (1<<6):
                TKS |= 1<<6
            else:
                TKS &= ~(1<<6)
        case 0o777564:
            if v & (1<<6):
                TPS |= 1<<6
            else:
                TPS &= ~(1<<6)
        case 0o777566:
            v &= 0xFF
            if not TPS & 0x80:
                return
            match v:
                case 13:
                    pass
                case _:
                    writeterminal(chr(v & 0x7F))
            TPS &= 0xff7f
            if TPS & (1<<6):
                threading.Timer(0.001, exec, ('''\
global TPS
import traceback
try:
    TPS |= 0x80; interrupt(INTTTYOUT, 4)
except:
    traceback.print_exc()
''',globals(),locals())).start()
            else:
                threading.Timer(0.001, exec, ('''\
global TPS
import traceback
try:
    TPS |= 0x80
except:
    traceback.print_exc()
''',globals(),locals())).start()
        case _:
            panic("write to invalid address " + ostr(a,6))
