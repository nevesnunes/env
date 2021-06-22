# +

- [gdb](./gdb.md)

- http://qira.me/
- https://github.com/rr-debugger/rr
- https://github.com/HyperDbg/HyperDbg
- https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview
- https://blog.ret2.io/2021/04/20/tenet-trace-explorer/

- http://man7.org/linux/man-pages/man1/nsenter.1.html

# version control

- git blame - reasons behind changes
- issues, pull requests - relate with source code

# methodologies

- http://yellerapp.com/posts/2014-08-11-scientific-debugging.html
    - timestamped log of problem statement, hypothesis, expected vs actual results
- https://mhandroid.wordpress.com/2011/01/25/how-cc-debugging-works-on-android/
    > Because gdbserver is attached to the already running process (as opposed to situation where process would be started by gdbserver) it can miss some code execution which take place soon after the application start.
    > [...] I usually write some endless while loop and then change the control variable after gdb is fully started.
- https://lobste.rs/s/h7f6qk/what_debugging_technique_did_it_take_you
    > If there’s a piece of code that’s not doing what you expect, add a loop around it whose condition is a variable that can be modified by the debugger. The resulting binary can be effectively unchanged such that the loop executes once, but if a debugger is present and you see the strange behavior, you can go back and step through it. 1a. This can also be done by modifying the instruction pointer, but that requires restoring register state. I do this too but it’s more tricky.
    > The unused portion of the stack often contains clues about what happened recently.
    > Break on access (ba in WinDbg) uses CPU registers to break on a memory address when it’s used. This is wonderful for tracking how state moves across a system, or tracking when locks are acquired and released, etc.
    > Using breakpoints with conditions allows things like breaking on a common thing, like opening a file, printing out the state of the operation, and resuming execution, allowing interesting conditions to be logged.
    > While very common, it’s also useful to get a debug memory allocator that can do things like mark pages as invalid on free (to generate access violations on use after free), or add a guard page after a memory allocation (to cause access violations on memory overruns.) A good one of these can also keep around allocation information after free for debugging, such as the stack that freed memory, and track the number of allocations to detect leaks.
    > Altering thread priorities in the debugger is one way to promote the code you’re trying to look at and/or demote code that’s interfering with you.
    > If you have a race condition, thoughtfully adding sleep in the right place can provoke it allowing it to be debugged and understood.
    > If code aborts in ways you don’t expect, add a breakpoint to the exception filter (which decides which handlers to execute.) This executes when the full stack that caused the exception to be raised is present.
    > Further to the previous comments about patching code, if you’re stepping through code and a branch goes somewhere you don’t want, change the instruction pointer. If you want that branch to happen again, change the condition jump to an unconditional jump.
    > In WinDbg, dps on import tables or import table entries to show where indirect calls will go. This is useful when something else is trying to hijack your code.
    > Keep an in memory circular log of interesting cases in your code. This log often doesn’t need to be big, and doesn’t need to allocate on insert, but if something bad happens in your code you can dump the interesting cases that were hit recently.
- https://www.quora.com/Programming-Interviews/Whats-the-hardest-bug-youve-debugged/answer/Dave-Baggett?srid=pxH3&share=1
    > Replace entire modules with stubs that pretend to do the real thing, but actually do something completely trivial that can't be buggy.
    > Reading and writing (I/O) involves precise timing. [...] the low-level code that reads and writes has to do so according to a clock. [...] I noticed that we set the programmable timer on the PlayStation 1 to 1 kHz (1000 ticks/second) [...] I modified the load/save code to reset the programmable timer to its default setting (100 Hz) before accessing the memory card, then put it back to 1 kHz afterwards. We never saw the read/write problems again.
    > But the gist of it was that crosstalk between individual parts on the motherboard, and the combination of sending data over both the controller port and the memory card port while running the timer at 1 kHz would cause bits to get dropped... and the data lost... and the card corrupted.
- https://blog.safia.rocks/post/170269021619/tips-for-reading-new-codebases
    - public-facing API

### concurrency

Ensuring atomicity, handling exceptions and reentrant calls:

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

### use-after-free

- https://pernos.co/examples/use-after-free

### cpu bug

- [772330 \- layout crashes with AuthenticAMD Family 20 \(0x14\), Models 1 and 2 CPUs \(also shows as AMD Radeon HD 6xxx series\), spiking at various times](https://bugzilla.mozilla.org/show_bug.cgi?id=772330#c21)

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

### APIs

- Try payload from API response endpoints vs. manually crafted.
