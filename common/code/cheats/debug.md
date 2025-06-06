# +

- unix
    - [gdb](./gdb.md)
    - http://qira.me/
    - https://github.com/rr-debugger/rr
    - http://man7.org/linux/man-pages/man1/nsenter.1.html
    - https://github.com/panda-re/panda
    - [GitHub \- brainsmoke/ptrace\-burrito: a friendly wrapper around ptrace](https://github.com/brainsmoke/ptrace-burrito)
- mac
    - [lldbinit/lldbinit\.py at master · gdbinit/lldbinit · GitHub](https://github.com/gdbinit/lldbinit/blob/master/lldbinit.py)
    - https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/
- windows
    - [x64dbg](./x64dbg.md)
    - [windbg](./windbg.md)
    - https://github.com/HyperDbg/HyperDbg
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview
    - [processes](./windows.md#debug)
    - [filesystems](./filesystem.md#debug)
- firmware / embedded systems: JTAG
    - https://openocd.org/doc-release/html/About.html#What-is-OpenOCD_003f
    - https://github.com/riscv/riscv-debug-spec
        - https://github.com/pulp-platform/riscv-dbg/blob/master/doc/debug-system.md

- [GitHub \- mahaloz/decomp2dbg: A plugin to introduce interactive symbols into your debugger from your decompiler](https://github.com/mahaloz/decomp2dbg)
- [GitHub \- bootleg/ret\-sync: ret\-sync is a set of plugins that helps to synchronize a debugging session \(WinDbg/GDB/LLDB/OllyDbg2/x64dbg\) with IDA/Ghidra/Binary Ninja disassemblers\.](https://github.com/bootleg/ret-sync)
- [Tenet: A Trace Explorer for Reverse Engineers \| RET2 Systems Blog](https://blog.ret2.io/2021/04/20/tenet-trace-explorer/)
- [GitHub \- EpicGamesExt/raddebugger: A native, user\-mode, multi\-process, graphical debugger\.](https://github.com/EpicGamesExt/raddebugger)
- [GitHub \- Wenzel/pyvmidbg: LibVMI\-based debug server, implemented in Python\. Building a guest aware, stealth and agentless full\-system debugger](https://github.com/Wenzel/pyvmidbg)

# implementation

- breakpoints - single-byte instruction overwritting address
    - https://eli.thegreenplace.net/2011/01/27/how-debuggers-work-part-2-breakpoints
- if no debugger attached, then interrupt handler sends SIGTRAP to threads
    - https://stackoverflow.com/questions/22379105/does-executing-an-int-3-interrupt-stop-the-entire-process-on-linux-or-just-the-c
- distinguishing ptrace trapped syscalls via `PTRACE_O_TRACESYSGOOD`
    - e.g. https://github.com/rapiz1/catp/blob/main/src/lib.rs

- https://code.woboq.org/linux/linux/arch/x86/include/asm/ptrace.h.html

- https://abda.nl/posts/understanding-ptrace/
- https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/
- https://lucasg.github.io/2016/11/27/How-to-Create-and-Debug-a-Process-on-Windows/
- https://aarzilli.github.io/debugger-bibliography/

# documentation

- implementation differentials/bugs outlined by RFCs: "Security Considerations" section, past versions, erratas
    - https://edoverflow.com/2022/reading-rfcs-for-bug-bounty-hunters/
- if software wasn't always tracked in vcs, then changelog files document changes in older versions
    - e.g. [CHANGES \- bash\.git \- bash](https://git.savannah.gnu.org/cgit/bash.git/tree/CHANGES)
- documentation isn't as detailed about borrowed semantics as older documentation where they were introduced
    - e.g. ssh vs rlogin escape characters
        - [linux \- Exit SSH connection with user switched inside in one step \- Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/454228/5132)
        - [unix\-history\-repo/cu\.c at usr/src/BSD\-SCCS\-Import · dspinellis/unix\-history\-repo · GitHub](https://github.com/dspinellis/unix-history-repo/blob/usr/src/BSD-SCCS-Import/usr/src/old/cu/cu.c#L29)
- documentation wasn't updated after fixed logic
    - e.g. cron support for ranges of lists of names
        - https://thenewstack.io/what-happens-when-you-find-a-decades-old-bug/
- older version of specification may directly address core conceptual issues

### version control

- git bisect - reduce regression test cases
    - [!] Can also find fixes instead of regressions
        - https://web.archive.org/web/20110715102644/http://www.worksmartlabs.com/blog/2011/07/13/sleuthing-git-using-git-or-regression-testing-done-backwards/
        ```bash
        # "good" means "not fixed yet", and "bad" means "fixed"
        git bisect start
        git bisect bad # i.e., the fix has been introduced in the latest version.
        git bisect good v1.7.0.4 # i.e., the bug still existed at this tag.
        ```
    - e.g. [GitHub \- mozilla/mozregression: Regression range finder for Mozilla nightly builds](https://github.com/mozilla/mozregression)
- git blame - reasons behind changes
- issues, pull requests - relate with source code

### mailing lists

- context / discussion on patches
    - [LKML\.ORG \- the Linux Kernel Mailing List Archive](https://lkml.org/)

### patents

- context on undocumented implementation details
    - e.g. [DEF CON 26 - Christopher Domas - GOD MODE UNLOCKED Hardware Backdoors in redacted x86](https://www.youtube.com/watch?v=jmTwlEh8L7g)

### papers

- start with earliest / most cited, which can describe a different implementation
    - e.g. DNA Cypher - n variants, earliest is "Hiding messages in DNA microdots"

# methodologies

- trace: make internal state explicit
    - chain relays to validate transformations
        > From your code, it appears that it should successfully change the values of request parameters. Perhaps try chaining a second instance of Burp as upstream proxy from the first, so that you can see the actual requests that are hitting the wire.
        - https://forum.portswigger.net/thread/automatically-modifying-request-parameters-8c3e71ff
    - validating parts vs whole
        > you may think of other things you can do with that exploit (ex: instead of RCE just leaking application secrets that can forge a cookie).  Or even just simplifying the exploit and instead of using it to get code execution, try putting in a sleep, DNS request, echo, etc to verify at least a piece of the exploit works. [...] you’ll see me do a bunch of enumeration from the exploit such as leaking java/OS version and environment variables which would have confirmed why the Remote Class Loading wasn’t working. The enumeration is simple, its just putting ${java:version} in the URL
        - https://thesecuritynoob.com/interviews/interview-with-ippsec-of-youtube-and-hackthebox/
    - visualizing internal structures
        > Browse data structures in Firefox. While my Lisp is running, a web browser runs in another thread, and every symbol has its own URL. Data structures are displayed as HTML tables. I can click on a field within an object in Firefox, and it goes to the object contained in that field, and displays that.
        - https://news.ycombinator.com/item?id=11383999
    - visualizing layout
        - https://raymii.org/s/articles/Rectangle_debugging_in_QML_just_like_printf.html
    - graphics diagnostics - flush screen with color
        > I tried to set the screen color to the value it reads when it exits the loop and then hard-lock so the color doesn’t get changed.
        - https://mgba.io/2020/01/25/infinite-loop-holy-grail/
    - checksum for replay
        > found a bunch of bugs waiting to happen (uninitalized variables / dangling pointer sort of stuff) that would trigger an error when replaying from a file didn't produce the same results as the original play (we had a checksum of game state that we could check)
        - https://news.ycombinator.com/item?id=27517391
    - multi-threaded interactions
        > with time-stamps, user-ids, user-agent strings, session-id, basic operations, you learn a lot about the running system and why it might have failed for one particular user.
        - https://blog.jvroom.com/2012/02/08/debugging-hard-problems/
    - using compile-time macros as instrumentation
        - ~/code/snippets/trace_returns.c
    - logging unique query patterns (check if we've seen it before, how often have we seen it, if it's new, log it)
        - https://florian.github.io/count-min-sketch/
    - logging variable values at each algorithm iteration
        - https://en.wikipedia.org/wiki/Trace_table
    - masks vs levels
        - [ACPI debug output: `/sys/module/acpi/parameters/debug_layer`](https://www.kernel.org/doc/Documentation/acpi/debug.txt)
    - structured logging
        - https://www.honeycomb.io/wp-content/uploads/2019/08/From-Unstructured-Logs-to-Observability-Honeycomb.pdf
        - https://www.honeycomb.io/wp-content/uploads/2018/07/Honeycomb-Guide-Achieving-Observability-v1.pdf
    - alternatives to debugger attaching to external process (i.e. Windows process creating remote thread)
        - patch jmp with offset 0 (i.e. jmp to self): `eb fe`
        - http://paulslaboratory.blogspot.com/2014/04/ebfe-debugging-remote-thread.html
    - alternatives to read memory / cpu context
        - instrument drivers, write to EFI variable / CMOS, then read from EFI shell
        - read opcodes from cache line using JTAG debugger
        - given memory dump, on windbg: `!for_each_module "s @#Base @#End ?? ?? ??"` and look for offsets within page (low 3 digits of the address) - they stay the same from boot to boot
        - https://twitter.com/ivanrouzanov/status/1503858933173211153
- diff: compare executions against baseline
    - query partitioning: generate several queries outputting disjoint subsets of original's set, then compare union of subsets with original's set
        > The core idea of Query Partitioning is to, starting from a given original query, derive multiple, more complex queries (called partitioning queries), each of which computes a partition of the result. The individual partitions are then composed to compute a result set that must be equivalent to the original query's result set. A bug in the DBMS is detected when these result sets differ.
        - e.g.
            ```sql
            CREATE TABLE t0(c0 INT);
            CREATE TABLE t1(c0 DOUBLE);
            INSERT INTO t0 VALUES (0);
            INSERT INTO t1 VALUES('-0');

            SELECT * FROM t0, t1; -- {0, -0}

            SELECT * FROM t0, t1 WHERE t0.c0 = t1.c0
            UNION ALL SELECT * FROM t0, t1 WHERE NOT(t0.c0 = t1.c0)
            UNION ALL SELECT * FROM t0, t1 WHERE (t0.c0 = t1.c0) IS NULL; -- {}
            ```
        - [Manuel Rigger \| Bugs found in Database Management Systems](https://www.manuelrigger.at/dbms-bugs/)
        - https://doi.org/10.1145/3428279
    - instruction counting
        - http://shell-storm.org/blog/A-binary-analysis-count-me-if-you-can/
- reduce: strip out unrelated code, filter traces
    - avoid watchpoint hits by patching-out instructions
        > - Using the Project64 debugger to set watchpoints on reads or writes to the controller state memory was fruitless because they were constantly triggered by code that I assume was generic system-level code checking and updating the controller state every frame.
        > - Instead I tried a more indirect approach with memory scanning on the Gallery menu. First I tracked down the location of the current button index with the standard technique of repeatedly updating the selection and then scanning memory for the newly changed value. Then I could set read watchpoints on the button index value to see if I could identify where the menu handling code was.
        > - Initially this also caused the watchpoint to trigger repeatedly. By patching out the read instruction that was repeatedly triggered, I saw it was caused by the glowing orange cursor that shows above the currently selected button. After removing that read instruction I got much more useful results: the watchpoint triggered when the menu description text for the currently selected button was changed, and when I pressed A to trigger the currently selected button.
        - https://jamchamb.net/2021/08/17/snap-station.html
    - trace down / learn up; make bite-sized changes
        - https://mitchellh.com/writing/contributing-to-complex-projects
    - verifying payloads against local server, JSON validation, alternatives in URL encoding, if hangs also happen with bad paths, other boolean-based checks...
        - [HackTheBox \- Laser \- YouTube](https://www.youtube.com/watch?v=vD3jSJlc0ro&t=2070s)
    - minimal cases
        - https://www.dataversity.net/debugging-complex-sql-queries/
        - https://tex.meta.stackexchange.com/questions/228/ive-just-been-asked-to-write-a-minimal-working-example-mwe-what-is-that
        - https://dba.stackexchange.com/help/minimal-reproducible-example
        - https://skerritt.blog/divide-and-conquer-algorithms/
        - https://en.wikipedia.org/wiki/Fractional_factorial_design
        - https://jvns.ca/blog/2022/03/23/a-toy-version-of-tls/
        - https://jvns.ca/blog/2022/11/06/making-a-dns-query-in-ruby-from-scratch/
            - use request from wireshark and dump response, then make our own request
        - [GitHub \- DRMacIver/shrinkray: Shrinkray is a modern multi\-format test\-case reducer](https://github.com/DRMacIver/shrinkray)
    - interactive examples
        - script for processing a chunk of bytes at a given step
            - e.g. [Server Handshake Keys Calc \- The Illustrated TLS 1\.3 Connection: Every Byte Explained](https://tls13.ulfheim.net/)
        - [New tool: Mess with DNS!](https://jvns.ca/blog/2021/12/15/mess-with-dns/)
        - [GitHub \- corkami/mitra: A generator of weird files \(binary polyglots, near polyglots\.\.\.\)](https://github.com/corkami/mitra)
- reshape: manipulate data to be consumed by format-specific tools
    - e.g. sqlite for sql queries on csv data
    - e.g. coreutils for line-oriented data
        - ~/bin/git-grep-detached.sh
        - ~/bin/plaintext-detached.sh
- dynamic analysis: understanding logic with the context of runtime state
    - 5 min rolling window for logging - space independent from duration
    - mock libc as alternative to strace
    - fault injecton via sandboxing as alternative to debugging
    - fault injecton on data to verify parsing
        - e.g. corrupting compressed graphics causes error in decompression routine; use unique byte pattern for memory search
    - remote host file to network relay
        > [...] the best logging method on WindowsCE is the use of remote debugging using a log file name of tcp://<ip-addr>:<port>.
        - https://gnupg.org/documentation/manuals/gnupg/Debugging-Hints.html
    - predictable attach after running
        > - Because gdbserver is attached to the already running process (as opposed to situation where process would be started by gdbserver) it can miss some code execution which take place soon after the application start.
        > - [...] I usually write some endless while loop and then change the control variable after gdb is fully started.
        - https://mhandroid.wordpress.com/2011/01/25/how-cc-debugging-works-on-android/
    - interrupt handler as alternative to attaching under debugger
        - e.g. Linux: USR1
    - attaching to debugger using trap
        - e.g. Mac OS 68k: `FKEY` resource containing `_Debugger trap + RTS instruction` and ID 7, invoke debugger with keybind `Command-Shift-7`
    - interactive flow control
        > - If there’s a piece of code that’s not doing what you expect, add a loop around it whose condition is a variable that can be modified by the debugger. The resulting binary can be effectively unchanged such that the loop executes once, but if a debugger is present and you see the strange behavior, you can go back and step through it. 1a. This can also be done by modifying the instruction pointer, but that requires restoring register state. I do this too but it’s more tricky.
        > - The unused portion of the stack often contains clues about what happened recently.
        > - Break on access (ba in WinDbg) uses CPU registers to break on a memory address when it’s used. This is wonderful for tracking how state moves across a system, or tracking when locks are acquired and released, etc.
        > - Using breakpoints with conditions allows things like breaking on a common thing, like opening a file, printing out the state of the operation, and resuming execution, allowing interesting conditions to be logged.
        > - Altering thread priorities in the debugger is one way to promote the code you’re trying to look at and/or demote code that’s interfering with you.
        > - If you have a race condition, thoughtfully adding sleep in the right place can provoke it allowing it to be debugged and understood.
        > - If code aborts in ways you don’t expect, add a breakpoint to the exception filter (which decides which handlers to execute.) This executes when the full stack that caused the exception to be raised is present.
        > - Further to the previous comments about patching code, if you’re stepping through code and a branch goes somewhere you don’t want, change the instruction pointer. If you want that branch to happen again, change the condition jump to an unconditional jump.
        > - In WinDbg, dps on import tables or import table entries to show where indirect calls will go. This is useful when something else is trying to hijack your code.
        > - Keep an in memory circular log of interesting cases in your code. This log often doesn’t need to be big, and doesn’t need to allocate on insert, but if something bad happens in your code you can dump the interesting cases that were hit recently.
        - https://lobste.rs/s/h7f6qk/what_debugging_technique_did_it_take_you
    - applying stack traces to general data
        - e.g. parsed tokens before error
            - https://discourse.elm-lang.org/t/techniques-for-debugging-parsers/3977
            ```
            (0,4) ExpectingDoubleQuote
            ---- with context stack ----
            (0,0) InString
            (0,0) InLiteral
            (0,0) InExpr
            ```
    - alternatives to breakpoints
        - infinite loop, optionally wrapped in trampoline with conditional logic
            - https://www.quanttec.com/fparsec/users-guide/debugging-a-parser.html
            ```
            let BP (p: Parser<_,_>) (stream: CharStream<_>) =
            // this will execute much faster than a
            // conditional breakpoint set in the debugger
            if stream.Line >= 100L then
                System.Diagnostics.Debugger.Break()
            p stream
            ```
    - alternatives to reverse debugging
        - vm snapshots
    - complementing static analysis
        > You’re going to have to stare at a code listing eventually. The problem is that you want to do it with as much information as possible so as to increase your accuracy. When you normally analyze a code listing for a defect you have some evidence of its existing behaviour: it works when you start with x but not with y, for example. In other words, you have something tangible to work from. Furthermore, those tangible inputs probably came from a system that affects you in some way, giving you a reason to care.
        - [Book review: The puzzling empathy of debugging](https://wozniak.ca/blog/2018/05/07/1/index.html)
- general guidelines
    - solving related problem
        > If you cannot solve the proposed problem try to solve first some related problem. Could you imagine a more accessible related problem? A more general problem? A more special problem? An analogous problem? Could you solve a part of the problem? Keep only a part of the condition, drop the other part; how far is the unknown then determined, how can it vary? Could you derive something useful from the data? Could you think of other data appropriate to determine the unknown? Could you change the unknown or the data, or both if necessary, so that the new unknown and the new data are nearer to each other?
        - [George Polya's Problem\-solving Tips](http://www.toroidalsnark.net/howto.html)
    - finding bugfixes in recent versions, build with debug symbols
        - https://blog.nelhage.com/post/computers-can-be-understood/#do-the-easy-thing-first
    - timestamped log of problem statement, hypothesis, expected vs actual results
        - http://yellerapp.com/posts/2014-08-11-scientific-debugging.html
    - [Testing and Debugging \- Dr\. Jody Paul](http://jodypaul.com/SWE/TD/TestDebug.html)
    - [Psychic debugging: Why Chinese characters don&\#039;t work \- The Old New Thing](https://devblogs.microsoft.com/oldnewthing/20120829-00/?p=6733)

### cross-pollination

- decomposing a problem and finding approaches for each identified property
    - [Dror HELPER: Unit testing patterns for Concurrent code \| UCP2019 \- YouTube](https://www.youtube.com/watch?v=tRe3ddG8O1Y)
    - [I'll Let Myself In: Tactics of Physical Pen Testers \- YouTube](https://www.youtube.com/watch?v=rnmcRTnTNC8)
- readable laser markings
    - refraction using tape
        > Use Scotch tape on an IC to more easily identify part markings. Just beware of ESD when removing!
        - https://twitter.com/joegrand/status/985962672683343872
    - lens polarizer
        > reject specular (shiny) reflections by placing one linear polarizer in front of your light source, then a second offset by 90 degrees in front of your camera lens.
        - https://www.reddit.com/r/netsec/comments/tk4no2/comment/i1oi5q4
        - https://twitter.com/azonenberg/status/1494061604161220615
- diff using light
    > Back in the day when I was poring over slightly different disassemblies, I'd print them both out, stack them, and look at them with a light behind them. That's how you diff old school.
    - https://twitter.com/babbageboole/status/1323442671730397184
- heating dispersal like air pockets in butterfly wings
    - [Publications on butterfly thin films as solar collectors](http://web.archive.org/web/20080720234650/http://it.stlawu.edu/~koon/lep_ref.html)
- solar panel folding like insect wings
    - [A Review of Bionic Design in Satellite Solar Wing Structures \- IOPscience](https://iopscience.iop.org/article/10.1088/1742-6596/1549/4/042099)

### APIs

- Try payload from API response endpoints vs. manually crafted.
- Start from public-facing API, tracing back to internals
    - https://blog.safia.rocks/post/170269021619/tips-for-reading-new-codebases

### memory corruption

- Check locations with no expected writes
    > - Set a breakpoint on A that sets the write watch on the value and continues execution then have a break point on B that disables the watch; check if value changed
    - https://stackoverflow.com/questions/42741370/how-to-debug-nondeterministic-memory-corruption
- Debugging version of malloc/free
    > - The version I use adds guard bytes before and after every allocation, and maintains an "allocated" list which free checks freed chunks against.
    > - Free should fill the freed memory with a known pattern (traditionally, 0xDEADBEEF ) It helps if allocated structures include a "magic number" element, and liberally include checks for the appropriate magic number before using a structure.
    > - verified on delete and causes a program triggered break point which automatically drops me into debugger.
    - https://softwareengineering.stackexchange.com/questions/252696/debugging-memory-corruption/252745
- Trigger access violations
    > - While very common, it’s also useful to get a debug memory allocator that can do things like mark pages as invalid on free (to generate access violations on use after free), or add a guard page after a memory allocation (to cause access violations on memory overruns.) A good one of these can also keep around allocation information after free for debugging, such as the stack that freed memory, and track the number of allocations to detect leaks.
    - https://lobste.rs/s/h7f6qk/what_debugging_technique_did_it_take_you
- Loop around allocations
- Allocation metadata
    - e.g. Windows pool tags
        - Object type / driver signature: `Tag`
        - Paging: `PoolType`
        - Bounds checking: `NumberofBytes`
        - Call stack of allocator / deallocator: [Pool Tracking \- Windows drivers \| Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/pool-tracking)
        - [An Introduction to Pool Tags \- Microsoft Tech Community](https://techcommunity.microsoft.com/t5/ask-the-performance-team/an-introduction-to-pool-tags/ba-p/372983)
        - [Windows NT Kernel memory pool tags](http://alter.org.ua/en/docs/win/pooltag/index1.php)
        - https://github.com/kodybrown/rktools2k3/blob/master/pooltag.txt
- [Memory corruption from outside the process looks like space aliens \- The Old New Thing](https://devblogs.microsoft.com/oldnewthing/20250123-00/?p=110800)

### concurrency

- Ensuring atomicity, handling exceptions and reentrant calls:
    ```cpp
    mutex_foo.lock();

    try {
        if (!is_foo_processed) {
            is_foo_processed = true;

            // ...

            // Avoid deadlock on reentrant calls
            mutex_foo.unlock();
            do_foo();
            mutex_foo.lock();

            // ...
        }
    } catch(...) {
        is_foo_processed = false;
        mutex_foo.unlock();
        throw;
    }

    mutex_foo.unlock();
    ```
- loop until hang/deadlock
    > If you know what part of the code produces it, you iterate over it indefinitely in a debugger until it hangs, then once you notice the iteration has stopped you “step in” to the debugger. Then you run another script that dumps the current trace back for each existing thread. That should be enough to detect the lock normally.
    - https://news.ycombinator.com/item?id=27518087
- in-memory logging with thread-id and time stamps
    > - Log as much as you could in the part where you think the bug is. Log every line that's run if you have to. You'll then skim through the log file looking for any unexpected patterns.
    > - ask yourself "what would break if a context switch happens right here" for each line.
    > - if you can pinpoint the place where the bug occurs, trigger a SIGSEGV there and run the entire thing under Valgrind.
    > - Back on the N64, I updated the bit of code that swapped threads to write, to a ring buffer, the outgoing/incoming PCs, thread IDs and clock. Found tons of unexpected issues. In another thread you can print that or save it to disk or whatever. Or just wait till it crashes and read memory for it. Found the last crash bug with it. Meanwhile, a colleague took it, and drew color coded bars on the screen so we could see exactly what was taking the time.
    - https://news.ycombinator.com/item?id=27647340
- Record before and after states in local vars, then log them after failure / event of interest, check they are consistent with expectations
    - :) avoids timing issues vs. adding logging to code block

### reverse debugging / time travel debugging

- [!] `rr` exits using the recorded process' exit code

```bash
echo -1 | sudo tee -a /proc/sys/kernel/perf_event_paranoid
echo 0 | sudo tee -a /proc/sys/kernel/kptr_restrict
rr ./foo
```

- increasing starvation in nondeterministic failures
    - `rr record -h`
        - https://robert.ocallahan.org/2016/02/introducing-rr-chaos-mode.html
        - [1237176 \- Intermittent test\_bfcache\.html \| Test timed out](https://bugzilla.mozilla.org/show_bug.cgi?id=1237176#c41)
        - [1203417 \- Intermittent layout/reftests/scrolling/fixed\-table\-1\.html \| image comparison \(==\), max difference: 165, number of differing pixels: 59976](https://bugzilla.mozilla.org/show_bug.cgi?id=1203417)
        - [1150737 \- Intermittent test\_remove\_objectStore\.html \| Test timed out](https://bugzilla.mozilla.org/show_bug.cgi?id=1150737#c197)
    - `sched_setattr(2)`
        - [GitHub \- osrg/namazu: 鯰: Programmable fuzzy scheduler for testing distributed systems](https://github.com/osrg/namazu)
        - [ZOOKEEPER\-2212: distributed race condition \- Namazu](http://osrg.github.io/namazu/post/zookeeper-2212/)
- atomicity violation for variable s_value
    1. run
    2. reverse-finish
    3. watch s_value
    4. reverse-continue
    - https://www.modernescpp.com/index.php/resolving-c-c-concurrency-bugs-more-efficiently-with-time-travel-debugging
- incorrect size used in page table walk
    1. c
    2. frame 13
    3. break tlb_set_page_with_attrs if vaddr == 0x4012a000
    4. rc
    5. break arm_cpu_handle_mmu_fault
    6. rc
    - https://translatedcode.wordpress.com/2015/05/30/tricks-for-debugging-qemu-rr/
    - https://lists.gnu.org/archive/html/qemu-devel/2015-05/msg05956.html

# case studies

- [Reasons why bugs might feel &\#34;impossible&\#34;](https://jvns.ca/blog/2021/06/08/reasons-why-bugs-might-feel-impossible/)
- [What does debugging a program look like?](https://jvns.ca/blog/2019/06/23/a-few-debugging-resources/)
- [nelhage debugs shit](https://nelhagedebugsshit.tumblr.com/)
- [Software Folklore ― Andreas Zwinkau](http://beza1e1.tuxen.de/lore/index.html)
- [GitHub \- danluu/debugging\-stories: A collection of debugging stories\. PRs welcome \(sorry for the backlog\) :\-\\)](https://github.com/danluu/debugging-stories)
- [Category:Games with debugging functions \- The Cutting Room Floor](https://tcrf.net/Category:Games_with_debugging_functions)
- [Lessons learned from 15 years of SumatraPDF, an open source Windows app](https://blog.kowalczyk.info/article/2f72237a4230410a888acbfce3dc0864/lessons-learned-from-15-years-of-sumatrapdf-an-open-source-windows-app.html)

### security

- [OffensiveCon22 \- Mark Dowd\- Keynote \-How Do You Actually Find Bugs? \- YouTube](https://www.youtube.com/watch?v=7Ysy6iA2sqA)
    - in-depth understanding of codebase leads to noticing idiosyncrasies that are exploitable when combined
        - [Issue 2232: XNU kernel use-after-free in mach_msg \- Monorail](https://bugs.chromium.org/p/project-zero/issues/detail?id=2232)
    - insufficient testing
        - [Project Zero: This shouldn't have happened: A vulnerability postmortem](https://googleprojectzero.blogspot.com/2021/12/this-shouldnt-have-happened.html)
    - look at different codebases to better understand a feature, see if one makes the mistake that the other carefully avoided
- [35C3 \-  The Layman&\#39;s Guide to Zero\-Day Engineering \- YouTube](https://www.youtube.com/watch?v=WbuGMs2OcbE)
    - understand architecture (build project, identify components from docs, then correlate with source code to reduce search space); security track record (CVEs); related work (PoCs)
        > exploit writeup, exploiting javascript engines, javascriptcore cve, javascriptcore vulnerability, webkit architecture, safari exploitdb, compile webkit, debugging webkit
    - identify sources of user input and follow the data through code paths; dumb fuzzing by bit-flipping that data
    - less coverage correlates with edge-cases
- [Keynote Day 2 | Hunting Evasive Vulnerabilities: Finding Flaws That Others Miss by James Kettle - YouTube](-https://www.youtube.com/watch?v=skbKjO8ahCI)
    - attention trap when picking techniques: look for behaviour, not technology
        - e.g. which inputs influence the response > is this input unkeyed and cached? > is this input unkeyed, cached, and harmful? > is this exploitable via cache poisoning?
        - [How "\.\./sms" could bypass Authy 2 Factor Authentication](https://sakurity.com/blog/2015/03/15/authy_bypass.html): implementation-specific input vs. sqli
    - test bad implementation of mitigation
        - [Security: Cross\-domain search timing](https://scarybeastsecurity.blogspot.com/2009/12/cross-domain-search-timing.html)
        - [761655 \- \(CVE\-2012\-1961\) Firefox ignores X\-Frame\-Options when set to SAMEORIGIN, SAMEORIGIN \(duplicated header\)](https://bugzilla.mozilla.org/show_bug.cgi?id=761655): iframe timing attack working even with X-Frame-Options header present
    - read original research since use cases change over time
        - [HTTP Request Smuggling](https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf): desync vs. waf bypass
    - make asking questions cheap
        - https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes
- [MARCO IVALDI: The INFILTRATE Effect: 6 Bugs in 6 Months](https://vimeo.com/474793702)
    - read docs, but don't believe
        ```sh
        umask 0; xscreensaver -log /etc/foo
        ln -s /etc/shadow .Xdefaults; Xorg :1 &; xlock -name user -display
        ```
- [Ned Williamson \- Attacking Chrome IPC \- 35c3](https://media.ccc.de/v/35c3-9579-attacking_chrome_ipc)
    - audit training: pick a report, try to find bug without looking at description, if you fail to spot the bug, ask what's missing in your process
- [From CTFs to Real\-Exploitation \(Part 3\)](https://dayzerosec.com/blog/2021/05/22/from-ctfs-to-real-exploitation-part-3.html)
    - sudoku approach: spot new gadgets and primitives you can chain with the vulnerability
        > - If you’ve got an info-leak, try leaking something else, try coercing the heap/stack into leaking something else, or reading another segment of memory. Then build an exploit off something else that you can leak.
        > - If its a write-primitive, find a new write-target.
        > - UAF, find a new object for the reuser, or maybe a new after-free path.
        > - Add a self-imposed restriction, deal with a mitigation even if its not implemented
        > - Require stability or portability
- https://sandboxescaper.blogspot.com/2022/06/how-to-get-into-bug-hunting.html
    1. Find an open source project
    2. Find an entry point for attacker controlled input
    3. Try to get a breakpoint for that entry point to hit in windbg
    4. Modify attacker controlled input to hit different code paths

### Using TTD for an ASAN deadlock

- [Ken Sykes on LinkedIn: We love hearing from people who use Time Travel Debugging \(TTD\) to…](https://www.linkedin.com/posts/ken-sykes-10ba9a3a_we-love-hearing-from-people-who-use-time-activity-7189613990388379648-YULH)
    > I threw the program into TTD and the problem reproduced immediately. From the trace, I could see all threads were blocked on a lock. From there, I rewound the trace to the start, setting a breakpoint on the locking functions, conditional on my specific blocking lock, then executed forward. Very quickly I could see that one location locked the lock, but its epilog ended up calling unlock with a different point.

### tracing miscompiled driver with kernel probes

- [Multi\-Kernel Drifting](https://luqman.ca/blog/multi-kernel-drifting/)

### how to catch pointer errors

- Use fenceposts around allocated blocks of memory
    - Check for unchanged fenceposts to detect over-writes
    - Check for fenceposts before a delete to detect attempts to delete addresses other than the start of an allocated block
- Add tracking info to allocated blocks indicating location of the allocation call
    - Scan heap at end of program for unrecovered blocks of memory
    - Report on locations from which those were allocated
- Add a freed bit to allocated blocks that is cleared when first allocated and set when the block is freed
    - Detect when a block is freed twice

- https://www.cs.odu.edu/~zeil/cs350/s21/Public/analysis/index.html

### caller not saving volatile register

- [Sometimes it \*is\* a compiler bug](https://quick-lint-js.com/blog/bug-journey/)
    - [Bug: dlltool delaylibs corrupt float/double arguments](https://lists.gnu.org/archive/html/bug-binutils/2022-05/msg00099.html)

### inconsistent view of file cache leaves zeros in code section

- [Compiler bug? Linker bug? Windows Kernel bug. \| Random ASCII \- tech blog of Bruce Dawson](https://randomascii.wordpress.com/2018/02/25/compiler-bug-linker-bug-windows-kernel-bug/)

### remote direct memory access marks page used by malloc during fork-exec

- [A Cursed Bug \- Made of Bugs](https://blog.nelhage.com/post/a-cursed-bug/)

### header prediction logic missing on bulk data receiver

- [Uncovering a 24\-year\-old bug in the Linux Kernel &\#8211; Skroutz Engineering](https://engineering.skroutz.gr/blog/uncovering-a-24-year-old-bug-in-the-linux-kernel/)
    - [TCP sender stuck in persist despite peer advertising non\-zero window](https://lore.kernel.org/netdev/87eelz4abk.fsf@marvin.dmesg.gr/T/#u)
    - [4.2.4. Header Prediction \- RFC 1323 \- TCP Extensions for High Performance](https://datatracker.ietf.org/doc/html/rfc1323#page-23)

### missing balanced token leads to false positive spurious token

- [pocorgtfo/README\.md at master · angea/pocorgtfo · GitHub](https://github.com/angea/pocorgtfo/blob/master/writeups/19/README.md#a-pdf-document-initially)
    > - Error: Ignoring spurious ET operator.
    > - Clearly here, the End Text tag ET is after the graphical state push q, unbalanced.

### file descriptor double close

- [Re: Weirdest Tomcat Behavior Ever? \- Paul Carter\-Brown \- org\.apache\.tomcat\.users \- MarkMail](https://tomcat.markmail.org/thread/bf6oz7ibxccvodd2)
    - tcp fin sent by tomcat, socket closed without close called explicitly, bad file descriptor expection caught
    - native library from jre was closing file descriptor twice, while tomcat was already using that fd as socket
    - [Debugging complex issues in web applications \- Mark Thomas \- YouTube](https://www.youtube.com/watch?v=UglxkO2Y5mU)

### bad synchronization

- [Re: Trouble with HTTP/2 during concurrent bulk data transfer \(server \-&gt; client\) \- Mark Thomas \- org\.apache\.tomcat\.users \- MarkMail](https://tomcat.markmail.org/thread/texcre345tmyn337)
    - avoid thread t1 clearing writeOperation state of thread t2 with reordered operations: t1 clear its state, then release semaphore
    - [Fix potential hang with concurrent reads or concurrent writes · apache/tomcat@92b9185 · GitHub](https://github.com/apache/tomcat/commit/92b91857)

### hardware timings

> - Replace entire modules with stubs that pretend to do the real thing, but actually do something completely trivial that can't be buggy.
> - Reading and writing (I/O) involves precise timing. [...] the low-level code that reads and writes has to do so according to a clock. [...] I noticed that we set the programmable timer on the PlayStation 1 to 1 kHz (1000 ticks/second) [...] I modified the load/save code to reset the programmable timer to its default setting (100 Hz) before accessing the memory card, then put it back to 1 kHz afterwards. We never saw the read/write problems again.
> - But the gist of it was that crosstalk between individual parts on the motherboard, and the combination of sending data over both the controller port and the memory card port while running the timer at 1 kHz would cause bits to get dropped... and the data lost... and the card corrupted.
- https://www.quora.com/Programming-Interviews/Whats-the-hardest-bug-youve-debugged/answer/Dave-Baggett?srid=pxH3&share=1

### y2k38 problem

- [&quot;Cannot initialize system file configuration&quot; · Issue \#21 · taviso/123elf · GitHub](https://github.com/taviso/123elf/issues/21#issuecomment-1140315604)
    > if you use -D_FILE_OFFSET_BITS=64 (which I do) you get stat64, which is supposed to handle these issues. I can see the kernel reports the correct result, but glibc just returns EOVERFLOW.

### github dumpster diving

```
# specific issues
site:https://github.com AND inurl:issues "race condition"

# dependency usage in other projects
site:https://github.com AND inurl:issues AND -inurl:foo "foo"
```

### recovering stderr messages

- [Slack's Secret STDERR Messages](https://www.brendangregg.com/blog/2021-08-27/slack-crashes-secret-stderr.html)
    ```bash
    shellsnoop $pid
    ```

### producers-consumers with bad notify call

- [Extreme Programming Challenge Fourteen The Bug](http://wiki.c2.com/?ExtremeProgrammingChallengeFourteenTheBug)

### reproducing race condition in test

1. [TonYApplicationMaster has race condition where thread is interrupted while flush is happening · Issue \#157 · tony\-framework/TonY · GitHub](https://github.com/tony-framework/TonY/issues/157)
    - `.close()` internally calls `.flush()`, exception thrown when `interrupt()` happens during the `.flush()`
2. [Fix race condition where thread is interrupted while flush is in progress by erwa · Pull Request \#158 · tony\-framework/TonY · GitHub](https://github.com/tony-framework/TonY/pull/158)
    - move `dataFileWriter.close()` call into the `stop()` method, after the event handler thread has terminated.
3. [Add regression test for issue \#157 by nevesnunes · Pull Request \#595 · tony\-framework/TonY · GitHub](https://github.com/tony-framework/TonY/pull/595)
    > This test ensures that when `interrupt()` is called, the EventHandler thread is not calling `dataFileWriter.close()`. In order to have a reproducable test and avoid flakyness, we mock the following methods to ensure the order and timming of the race condition:
    > - `dataFileWriter.close()` is locked on a latch until an `interrupt()` is sent, if that interrupt happens inside this call, it will cause an assertion fail;
    > - `interrupt()` unlocks that latch after executing the real implementation;

### reproducing dangling pointer in game engine

- [prevent appearance of dangling pointers in corpse queue · coelckers/gzdoom@a9ad3d1 · GitHub](https://github.com/coelckers/gzdoom/commit/a9ad3d1fc3c97a0dbf8cbe55bf8b3f9d329c98ea)

### resource leaks

- https://randomascii.wordpress.com/2021/07/25/finding-windows-handle-leaks-in-chromium-and-others/
    - derived measure: outstanding count of handles = created but not deleted across time

### memory corruption

- [Debugging a use\-after\-free in gdb](https://pernos.co/examples/use-after-free)

### confusing size of buffer with size of structure

> - Function a() called function b(). When function b() returned, a local variable in function a() had changed from 0 to 1. "Aha!" you say. "You're smashing the stack! Function b() is writing outside its stack frame." But function b() was provably not doing that.

> - Function b() called msgrcv(), which has a very badly designed API. It takes a pointer to a structure, and a size parameter. The structure is supposed to be a type field (long), and then a buffer (array of char). The size parameter is supposed to be the size of the buffer, not the size of the structure. The original code that implemented this came from a contractor, and they made the very natural mistake of putting the size of the whole structure in the size field. This meant that an extra long was read from the message queue, and smashed the stack.

> - But that should mess up the stack from from function b(). How did it mess up a variable in function a()? Well, the compiler put that variable in a register, not on the stack. So when b() was called, it had to save off the registers it was going to use, so a()'s local variable wound up in b()'s stack frame.

- https://news.ycombinator.com/item?id=9956129

### bad reference count

- library not unloading due to ref count bump from call to GetModuleHandleExW()
    - Validation: On WinDbg: `bm *GetModuleHandle*`, proc address argument in library mmap
    - [Debugging a Dynamic Library that Wouldn't Unload \- ForrestTheWoods](https://www.forrestthewoods.com/blog/debugging-a-dynamic-library-that-wouldnt-unload/)

### segv on invalid breakpoints

> - This occurs when gdb sets breakpoints on various probe events in the dynamic loader. The probe event locations are exported from ld.so as SDT markers, but gdb needs to know whether ARM or Thumb instructions are being exported at each marker so that it can insert the appropriate breakpoint instruction sequence. It does this by mapping the probe location to a function symbol (see arm_pc_is_thumb in gdb/arm-tdep.c), and using the target address of the symbol to determine if the function is called in Thumb or ARM more (bit 0 of the target address will be set for Thumb mode).

> - The problem here is that gdb can't map any of the probes to a symbol if the debug symbols aren't installed, and arm_pc_is_thumb returns false in this case (indicating ARM instructions).

- [Bug \#1576432 “gdb crashes when trying to start a debugging sessi\.\.\.” : Bugs : gdb](https://bugs.launchpad.net/gdb/+bug/1576432)

### nested symbol lookups unconditionally reset register restoration

```
commit 84088310ce06bfc5759b37f0cd043dce80f578b6
Author: Ulrich Drepper <drepper@redhat.com>
Date:   Tue Aug 25 10:42:30 2009 -0700

    Handle AVX saving on x86-64 in interrupted smbol lookups.

    If a signal arrived during a symbol lookup and the signal handler also
    required a symbol lookup, the end of the lookup in the signal handler reset
    the flag whether restoring AVX/SSE registers is needed.  Resetting means
    in this case that the tail part of the outer lookup code will try to
    restore the registers and this can fail miserably.  We now restore to the
    previous value which makes nesting calls possible.
```

- [519081 &ndash; Random crashes with ld\-linux loader on x86\_64](https://bugzilla.redhat.com/show_bug.cgi?id=519081)

### cpu bug

- [772330 \- layout crashes with AuthenticAMD Family 20 \(0x14\), Models 1 and 2 CPUs \(also shows as AMD Radeon HD 6xxx series\), spiking at various times](https://bugzilla.mozilla.org/show_bug.cgi?id=772330#c21)

### socket leaks

> - Netty has a boss thread that accepts incoming connections and assigns each successfully-opened socket to a single particular I/O thread.

> - Each I/O thread runs an infinite loop that repeatedly waits for activity on its assigned sockets (using epoll/kqueue/select) and runs each received TCP segment through our Netty pipeline on that thread.

> - Usually when an I/O thread writes to one of its own sockets, the write takes place synchronously. However, crucially, it may defer at least part of the write until later, for example if the kernel’s buffer is full. The write would then be performed on a later loop when the selector (epoll/kqueue/select) reports that the socket is ready for writing.

> - We were writing to a channel and then blocking on the result Future to see if it succeeded. Since we were writing from the I/O thread, the write would usually be performed synchronously so the returned future would already be complete and the application would continue. However, sometimes the write wouldn’t fully complete and the future could not be completed until the next time around the selector loop. But the I/O thread was blocked, so the loop couldn’t proceed, so the future would never complete.

> - Since the I/O thread was stuck, it couldn’t respond to any further messages from any of its managed sockets. Eventually the client would give up and send a FIN segment, and the kernel’s TCP/IP stack would put the socket in the CLOSE_WAIT state. Usually the I/O thread handles this in its worker loop by calling close on the socket, but it was stuck so this code never ran and the socket would never close.

> - The boss thread was still running, so the system continued to accept new connections and assign some of them to the stuck I/O thread.

- https://news.ycombinator.com/item?id=18479681

### non-compliant implementations

> - When BIND started, it would take our root hints, load them into it's cache, and begin to perform AAAA queries for the root servers. One of the upstream servers would respond with 0 records, the other would respond with NXDOMAIN. The server that responded with NXDOMAIN, would subsequently get deleted from our BIND servers cache, and would no longer be used as a root.

> - The next question was why?

> - After some sleuthing through the DNS RFCs, I eventually found the answer. There are two ways for a DNS server to return that an answer to a query doesn't exist. Returning 0 records, and returning NXDOMAIN, and they have slightly different meaning. Returning 0 records, means that the label (think example.cm) exists, but the type of record does not (AAAA doesn't exist, but A/SRV/TXT/etc might). Returning NXDOMAIN means the the label doesn't exists, for any type of record, so don't bother querying me again for a different record type (There may have been some vagueness around this, I don't remember).

> The second discovery, is that we had a typo in our configuration, what we configured as the name of that root server, didn't match what our GRX provider had configured, which is why we were getting NXDOMAIN on one but not all servers we had configured as our roots.

> - The next question was why were our old servers working? This typo was actually duplicated from our older servers... which still worked during that outage.

> - So using my simulation, I tested every version of BIND released across something like a 3 year period, until I found it. Older version of BIND interpreted NXDOMAIN the same as 0 record answer, and at some point, I can only assume they fixed a bug, that updated this interpretation of NXDOMAIN.

- https://news.ycombinator.com/item?id=18478816

### shellcmd

[Can&\#39;t open file \(win gvim\) · Issue \#48 · mattn/vim\-gist · GitHub](https://github.com/mattn/gist-vim/issues/48)

This is not a permissions problem, and windows DOES in fact unset read-only. It's just a GUI bug that it thinks the bit is set. If you don't believe me, bring up the command prompt, cd to where the folder is, then do: dir /a:r. The folder you turned read-only off will not appear, because it really IS off.

The problem is really with the system() call. Just doing this from within vim will reproduce it:

```
:echo system("echo hi")
```

The problem is because some shell like cygwin shell is being used. I put these commands at the top of my `_vimrc` file to solve the problem:

```
set shell=cmd
set shellcmdflag=/c
```

This problem is solved now. I am not certain why this fixes it, because it seems like a race condition where the tmp file is created and closed before the process is done using it. The tmp file is in fact created successfully (I saw this with procmon), but it is closed/deleted before it's truely done with it.
