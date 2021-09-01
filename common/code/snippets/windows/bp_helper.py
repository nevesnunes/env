breakpoints = []

def add_bp(symbol, nargs, thiscall):
    global breakpoints
    module_name = symbol.split("!")[0] 
    function_name = symbol.split("!")[1]
    module = pykd.module(module_name)
    module.reload()
    breakpoints.append((pykd.setBp(module.offset(function_name), breakCount),function_name, nargs, thiscall))
    print "Breakpoint %d added %s" % (len(breakpoints), symbol)

def print_call(breakpoint):
    global breakpoints
    out = ""
    esp = pykd.reg("esp")
    ecx = pykd.reg("ecx")
    bp, function_name, nargs, thiscall = breakpoints[breakpoint]
    out += "%s ( " % (function_name)
    if thiscall:
        out += "%s, " % hex(ecx)
    if nargs:
        out += ", ".join(map(hex,pykd.loadDWords(esp+0x4,nargs)))
    out += " )"
    return out