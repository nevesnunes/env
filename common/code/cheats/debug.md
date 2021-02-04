# +

- [gdb](./gdb.md)
- https://github.com/HyperDbg/HyperDbg

- http://man7.org/linux/man-pages/man1/nsenter.1.html

# version control

- git blame - reasons behind changes
- issues, pull requests - relate with source code

# methodologies

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
- https://blog.safia.rocks/post/170269021619/tips-for-reading-new-codebases
    - public-facing API

# case studies

https://github.com/mattn/gist-vim/issues/48

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

---

I've noticed that you commented the contents of the attachment and not the "<urn1:attach>...</urn1:attach>" itself. This is probably a source of errors.
Anyway, my suggestion would be to:
    - Create the document you want to create manually on Content Server.
    - Execute GetNode to retrieve that document.
    - Recreate the CreateDocument request by copying the relevant parts from the GetNode response and omitting the attachment.
        - You just need to change the name to avoid a conflict.
        - You have to be careful with the namespaces.
    - Add the attachment and try again.
By doing this you will limit the problem. For example:
    - By doing 1 and 2 you ensure you're not encoding things wrongly since the API gives you the exact values you need to use when creating a new document.
    - By doing 3 you test the simplest case first.
    - If you reach 4, then you know the problem is exclusively related with the content and you can focus there.
