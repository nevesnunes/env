#!/usr/bin/env perl

# See:
# https://linux.die.net/man/1/winedbg

use strict;
use warnings;
use lib $ENV{RLWRAP_FILTERDIR};
use RlwrapFilter;
use String::ShellQuote qw( shell_quote );

my $txt = <<END;
abort, Aborts the debugger.
attach <N>, Attach to a Wine-process (N is its ID, numeric or hexadecimal). IDs can be obtained using the info process command. Note the info process command returns hexadecimal values
break, Adds a breakpoint at current PC address.
break <id>, Adds a breakpoint at the address of symbol <id>
break <id> <N>, Adds a breakpoint at the line N inside symbol <id>.
break * <N>, Adds a breakpoint at address N
break <N>, Adds a breakpoint at line N of current source file.
bt <N>, Print calling stack of thread of ID N. Note: this doesn't change the position of the current frame as manipulated by the up & dn commands).
bt, Print calling stack of current thread.
cond N <expr>, Adds condition <expr> to (break|watch)-point #N. <expr> will be evaluated each time the (break|watch)-point is hit. If the result is a zero value, the breakpoint isn't triggered.
cond <N>, Removes any existing condition to (break|watch)-point N
cont, Continue execution until next breakpoint or exception.
del display <N>, undisplay <N>, Deletes display #N
delete, Deletes (break|watch)-point #N
detach, Detach from a Wine-process.
dir, Deletes the list of dir:s where to look for source files
dir <pathname>, Adds <pathname> to the list of dir:s where to look for source files
disable, Disables (break|watch)-point #N
disas, Disassemble from current position
disas <expr>, Disassemble from address <expr>
disas <expr>, <expr>, Disassembles code between addresses specified by the two <expr>:s
display <expr>, Adds a display for expression expr>
display /fmt <expr>, Adds a display for expression <expr>. Printing evaluated <expr> is done using the given format (see print command for more on formats)
dn, Goes down one frame in current thread's stack
dn <N>, Goes down N frames in current thread's stack
enable <N>, Enables (break|watch)-point #N
finish, Execute until return of current function is reached.
frame <N>, Sets N as the current frame for current thread's stack.
help info, Prints some help on info commands
help, Prints some help on the commands.
info all-regs, Prints the value of the CPU and Floating Point registers
info break, Lists all (break|watch)-points (with their state).
info class <id>, Prints information on Windows's class <id>
info class, Lists all Windows' class registered in Wine
info display, Lists the active displays
info frame, Lists the exception frames (starting from current stack frame). You can also pass, as optional argument, a thread id (instead of current thread) to examine its exception frames.
info locals, Prints information on local variables for current function frame.
info map, Lists all virtual mappings used by the debugged program
info map <N>, Lists all virtual mappings used by the program of pid N
info process, Lists all w-processes in Wine session
info regs, Prints the value of the CPU registers
info segment, Lists all allocated segments (i386 only)
info segment <N>, Prints information on segment N (i386 only)
info share, Lists all the dynamic libraries loaded in the debugged program (including .so files, NE and PE DLLs)
info share <N>, Prints information on module at address N
info stack, Prints the values on top of the stack
info thread, Lists all w-threads in Wine session
info wnd, Displays the window hierarchy starting from the desktop window
info wnd <N>, Prints information of Window of handle N
kill
list <123, 234>, lists source lines from line 123 up to line 234 in current file
list <foo.c:1,56>, lists source lines from line 1 up to 56 in file foo.c
list <id>, Lists 10 source lines of function <id>
list -, Lists 10 source lines backwards from current position
list, Lists 10 source lines forwards from current position.
list * <N>, Lists 10 source lines from address N
list <N>, Lists 10 source lines from line #N in current file
list <pathname>:<N>, Lists 10 source lines from line #N in file <pathname>
minidump file.mdmp, saves the debugging context of the debuggee into a minidump file called file.mdmp]
monitor mem, Displays memory mapping of debugged process
monitor proc, Lists all processes in the Wine session
monitor wnd, Lists all window in the Wine session
next, Continue execution until next C line of code (doesn't enter function call)
nexti, Execute next assembly instruction (doesn't enter function call)
pass, Pass the exception event up to the filter chain.
print <expr>, Prints the value of <expr> (possibly using its type)
print /fmt <expr>, Prints the value of <expr> (possibly using its type)
quit, Exits the debugger.
rwatch <id>, Adds a watch command (on read) at the address of symbol <id>. Size depends on size of <id>.
rwatch * <N>, Adds a watch command (on read) at address N (on 4 bytes).
set fixme - all, Turns off the 'fixme' class on all channels
set <var> = <expr>, Writes the value of <expr> in <var> variable.
set warn + win, Turns on warn on 'win' channel
set - win, Turns off warn/fixme/err/trace on 'win' channel
set + win, Turns on warn/fixme/err/trace on 'win' channel
show dir, Prints the list of dir:s where source files are looked for.
step, Continue execution until next C line of code (enters function call)
stepi, Execute next assembly instruction (enters function call)
symbolfile <pathname>, Loads external symbol definition symbolfile <pathname>
symbolfile <pathname> <N>, Loads external symbol definition symbolfile <pathname> (applying an offset of N to addresses)
up, Goes up one frame in current thread's stack
up <N>, Goes up N frames in current thread's stack
watch <id>, Adds a watch command (on write) at the address of symbol <id>. Size depends on size of <id>.
watch * <N>, Adds a watch command (on write) at address N (on 4 bytes).
whatis <expr>, Prints the C type of expression <expr>
x <expr>, Examines memory at <expr> address
x /fmt <expr>, Examines memory at <expr> address using format /fmt
END

my $filter = RlwrapFilter->new;
$filter->completion_handler(\&completion);
$filter->run;

sub completion {
  my ($input, $prefix, @completions) = @_;
  $input =~ s/\s+/ /g;

  my $cmd1 = 'echo "'.$txt.'"';
  my $cmd2 = shell_quote('fzf', '-0', '-1', '-q', $input, '--preview', 'echo {} | sed "s/,\s*/\n\t/"', '--preview-window', 'down:4:wrap');
  my $output = qx{$cmd1 | $cmd2};
  $output =~ s/^([^,<]*).*/$1/;
  $output =~ s/^\s+|\s+$//g;
  return $output;
}
