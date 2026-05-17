local exports = {
    name = "fuzz",
    version = "0.0.1",
    description = "Coverage-guided fuzzer for i286",
    license = "BSD-3-Clause",
    author = { name = "flib" },
}
local fuzz = exports

local cpu
local snap_addrs = { }
local start_bps = { 0xb01a8, }
local end_bps = { 0xf0613, }
local regs = {
    all = { "IP", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "ES", "ESBASE", "ESLIMIT", "ESFLAGS", "CS", "CSBASE", "CSLIMIT", "CSFLAGS", "SS", "SSBASE", "SSLIMIT", "SSFLAGS", "DS", "DSBASE", "DSLIMIT", "DSFLAGS", "GENFLAGS", "GDTRBASE", "GDTRLIMIT", "IDTRBASE", "IDTRLIMIT", "LDTR", "LDTRBASE", "LDTRLIMIT", "LDTRFLAGS", "TR", "TRBASE", "TRLIMIT", "TRFLAGS", "MSW", "V", "HALT" },
    pc = { "IP" },
}
-- TODO: local spacemap = { } for ram devices
local reset_subscription, stop_subscription

function fuzz.startplugin()
    local function pc()
        local cs = cpu.state["CS"].value
        local ip = cpu.state["IP"].value
        return (cs << 4) | ip
    end

    local function cb()
        if manager.machine.debugger.execution_state == "stop" then
            local pc = pc()
            if start_bps[pc] and not snap_addrs[pc] then
                maybe_take_snapshot()
            end
            if end_bps[pc] then
                maybe_save_coverage()
                print(string.format("PC = %08x", pc))
            end
            return
        end
    end

    function exists(file)
        local ok, err, code = os.rename(file, file)
        if (not ok) and (code == 13) then
            -- Permission denied, but file exists.
            return true
        end
        return ok
    end

    local function maybe_save_coverage()
        -- TODO: Check if instruction coverage set is distinct from already stored snapshots by comparing checksums.
        -- On reset: `trace /tmp/f,,noloop`, on start_bp: `:>/tmp/f`
    end

    local function maybe_take_snapshot()
        local path = os.execute(string.format("mkdir -p '%s'", os.getenv("HOME").."/tmp/fuzz/baseline"))
        if not exists(path.."/") then
            take_snapshot("baseline")
        end
    end

    local function hexdump(data, n)
        for i = 0, n-1 do
            io.write(string.format("%04x: ", i*0x10))
            for j = 1, 0x10 do
                io.write(string.format("%02x ", string.byte(data, i*0x10+j)))
            end
            io.write("\n")
        end
    end

    local function take_snapshot(name)
        local b, s, n = os.execute(string.format("mkdir -p '%s/%s'", os.getenv("HOME").."/tmp/fuzz", name))
        if n ~= 0 then
            print(string.format("Failed to create '%s', exit='%d'.", name, n))
            os.exit(1)
        end

        -- manager.machine.memory.regions[region]
        -- manager.machine.memory.shares[tag]
        -- vram_handler = mem:install_write_tap(REG_VRAMADDR, REG_VRAMMOD + 1, "vram", addon.onVramWrite) -- (offset, data)
        local mem = cpu.spaces["program"]
        if not mem then
            print("Missing space 'program'.")
            os.exit(1)
        end

        -- Store 0x10000-sized segments.
        -- TODO: Include banked maps.
        local start_addr = 0xf0000
        local data = mem:read_range(start_addr, start_addr + 0xffff, 8, nil)
    end

    local function mutate_reg_u16(src, val)
        -- TODO: Prefer seeds that cover new paths: https://www.fuzzingbook.org/html/MutationFuzzer.html#Guiding-by-Coverage
    end

    reset_subscription = emu.add_machine_reset_notifier(function ()
        print(string.format("Fuzzer started with ROM='%s'.", emu.romname()))

        -- Sanity checks.
        if not manager.machine.debugger then
            print("Missing debugger.")
            os.exit(1)
        end

        cpu = manager.machine.devices[":maincpu"]
        if not cpu or not cpu.debug then
            print("Missing or invalid device ':maincpu'.")
            os.exit(1)
        end

        -- Prepare snapshots dir.
        local b, s, n = os.execute(string.format("mkdir -p '%s'", os.getenv("HOME").."/tmp/fuzz"))
        if n ~= 0 then
            print(string.format("Failed to create 'tmp/fuzz', exit='%d'.", n))
            os.exit(1)
        end

        -- Convert lists to sets.
        for _, l in ipairs(start_bps) do start_bps[l] = true end
        for _, l in ipairs(end_bps) do end_bps[l] = true end
        for _, l in ipairs(regs.all) do regs.all[l] = true end

        -- Break on addresses where state is fuzzed.
        -- luaengine_debug.cpp @ device_debug_type.set_function("bpset", ...);
        for i, b in pairs(start_bps) do
            cpu.debug:bpset(b, "", "")
        end

        emu.register_periodic(cb)
    end)

    stop_subscription = emu.add_machine_stop_notifier(function ()
        print(string.format("Fuzzer stopped."))
    end)
end

return exports
