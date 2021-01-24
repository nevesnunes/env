import angr

proj = angr.Project('/bin/true', load_options={"auto_load_libs": False})

proj.factory.block(proj.entry).pp()
# 0x4013e2:       xor     ebp, ebp
# 0x4013e4:       mov     r9, rdx
# 0x4013e7:       pop     rsi
# 0x4013e8:       mov     rdx, rsp
# 0x4013eb:       and     rsp, 0xfffffffffffffff0
# 0x4013ef:       push    rax
# 0x4013f0:       push    rsp
# 0x4013f1:       mov     r8, 0x403c60
# 0x4013f8:       mov     rcx, 0x403bf0
# 0x4013ff:       mov     rdi, 0x401340
# 0x401406:       call    0x401190

proj.factory.block(cfg.kb.functions.function(name="main").addr).pp()