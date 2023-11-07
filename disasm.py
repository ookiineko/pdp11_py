rs = ("R0", "R1", "R2", "R3", "R4", "R5", "SP", "PC")
disasmtable = (
    (0o077700, 0o005000, "CLR", "D", True),
    (0o077700, 0o005100, "COM", "D", True),
    (0o077700, 0o005200, "INC", "D", True),
    (0o077700, 0o005300, "DEC", "D", True),
    (0o077700, 0o005400, "NEG", "D", True),
    (0o077700, 0o005700, "TST", "D", True),
    (0o077700, 0o006200, "ASR", "D", True),
    (0o077700, 0o006300, "ASL", "D", True),
    (0o077700, 0o006000, "ROR", "D", True),
    (0o077700, 0o006100, "ROL", "D", True),
    (0o177700, 0o000300, "SWAB", "D", False),
    (0o077700, 0o005500, "ADC", "D", True),
    (0o077700, 0o005600, "SBC", "D", True),
    (0o177700, 0o006700, "SXT", "D", False),
    (0o070000, 0o010000, "MOV", "SD", True),
    (0o070000, 0o020000, "CMP", "SD", True),
    (0o170000, 0o060000, "ADD", "SD", False),
    (0o170000, 0o160000, "SUB", "SD", False),
    (0o070000, 0o030000, "BIT", "SD", True),
    (0o070000, 0o040000, "BIC", "SD", True),
    (0o070000, 0o050000, "BIS", "SD", True),
    (0o177000, 0o070000, "MUL", "RD", False),
    (0o177000, 0o071000, "DIV", "RD", False),
    (0o177000, 0o072000, "ASH", "RD", False),
    (0o177000, 0o073000, "ASHC", "RD", False),
    (0o177400, 0o000400, "BR", "O", False),
    (0o177400, 0o001000, "BNE", "O", False),
    (0o177400, 0o001400, "BEQ", "O", False),
    (0o177400, 0o100000, "BPL", "O", False),
    (0o177400, 0o100400, "BMI", "O", False),
    (0o177400, 0o101000, "BHI", "O", False),
    (0o177400, 0o101400, "BLOS", "O", False),
    (0o177400, 0o102000, "BVC", "O", False),
    (0o177400, 0o102400, "BVS", "O", False),
    (0o177400, 0o103000, "BCC", "O", False),
    (0o177400, 0o103400, "BCS", "O", False),
    (0o177400, 0o002000, "BGE", "O", False),
    (0o177400, 0o002400, "BLT", "O", False),
    (0o177400, 0o003000, "BGT", "O", False),
    (0o177400, 0o003400, "BLE", "O", False),
    (0o177700, 0o000100, "JMP", "D", False),
    (0o177000, 0o004000, "JSR", "RD", False),
    (0o177770, 0o000200, "RTS", "R", False),
    (0o177777, 0o006400, "MARK", "", False),
    (0o177000, 0o077000, "SOB", "RO", False),
    (0o177777, 0o000005, "RESET", "", False),
    (0o177700, 0o006500, "MFPI", "D", False),
    (0o177700, 0o006600, "MTPI", "D", False),
    (0o177777, 0o000001, "WAIT", "", False),
    (0o177777, 0o000002, "RTI", "", False),
    (0o177777, 0o000006, "RTT", "", False),
    (0o177400, 0o104000, "EMT", "N", False),
    (0o177400, 0o104400, "TRAP", "N", False),
    (0o177777, 0o000003, "BPT", "", False),
    (0o177777, 0o000004, "IOT", "", False)
)

def disasmaddr(m,a):
    if m & 7 == 7:
        match m:
            case 0o27: a[0]+=2;return "$" + oct(memory[a[0]>>1])[2:]
            case 0o37: a[0]+=2;return "*" + oct(memory[a[0]>>1])[2:]
            case 0o67: a[0]+=2;return "*" + oct(a[0] + 2 + memory[a[0]>>1] & 0xFFFF)[2:]
            case 0o77: a[0]+=2;return "**" + oct(a[0] + 2 + memory[a[0]>>1] & 0xFFFF)[2:]
    r = rs[m & 7]
    match m & 0o70:
        case 0o00: return r
        case 0o10: return f'({r})'
        case 0o20: return f'({r})+'
        case 0o30: return f'*({r})+'
        case 0o40: return f'-({r})'
        case 0o50: return f'*-({r})+'
        case 0o60: a[0]+=2; return oct(memory[a[0]>>1])[2:] + f'({r})'
        case 0o70: a[0]+=2; return "*" + oct(memory[a[0]>>1])[2:] + f'({r})'

def disasm(a):
    msg = None
    ins = memory[a>>1]
    for l in disasmtable:
        if ins & l[0] == l[1]:
            msg = l[2]
            break
    if msg == None:
        return "???"
    if l[4] and ins & 0o100000: msg += "B"
    s = (ins & 0o7700) >> 6
    d = ins & 0o77
    o = ins & 0o377
    aa = [a]
    match l[3]:
        case "SD" | "D":
            if l[3] == "SD":
                msg += " " + disasmaddr(s, aa) + "," # fallthrough
            msg += " " + disasmaddr(d, aa)
        case "RO" | "O":
            if l[3] == "RO":
                msg += " " + rs[(ins & 0o700) >> 6] + ","; o &= 0o77 # fallthrough
            if o & 0x80:
                msg += " -" + oct(2*((0xFF ^ o)) + 1)[2:]
            else:
                msg += " +" + oct(2*o)[2:]
        case "RD": msg += " " + rs[(ins & 0o700) >> 6] + ", " + disasmaddr(d, aa)
        case "R": msg += " " + rs[ins & 7]
        case "R3": msg += " " + rs[(ins & 0o700) >> 6]
    return msg
