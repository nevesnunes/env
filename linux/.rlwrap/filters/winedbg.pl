#!/usr/bin/env perl

# See:
# https://unix.stackexchange.com/questions/272710/rlwrap-tclsh-multi-word-autocompletion

use strict;
use warnings;
use lib $ENV{RLWRAP_FILTERDIR};
use RlwrapFilter;

my @cmds = qw(
abort
attach
break
bt
cond
condition
cont
delete
detach
dir
disable
disassemble
display
dn
down
enable
finish
frame
help
info
kill
list
monitor
next
nexti
pass
print
quit
rwatch
set
show
step
stepi
symbolfile
undisplay
up
watch
whatis
x
);

my $txt = <<END;
attach 0x
delete display
disable display
enable display
help info
info all-regs
info break
info class
info display
info frame
info locals
info map
info process
info regs
info segment
info share
info stack
info thread
info wnd
local display
monitor mem
monitor proc
monitor wnd
set fixme - all
set warn + win
set - win
set + win
show dir
END

my @multi;
foreach my $line (split /\n/, $txt) {
  $line =~ s/\?//g;
  $line =~ s/ - -/ --/g;
  $line =~ s/ \.\.\.//g;
  $line =~ s/\s{2,}/ /g;
  $line =~ s/\s+$//;
  push @multi, $line;
  if ($line =~ /^(.*\s)(-\w+)\s(-\w+)(.*)$/) {
    push @multi, "$1$3 $2$4";
  }
}

my $filter = RlwrapFilter->new;
$filter->completion_handler(\&completion);
$filter->run;

sub completion {
  my ($input, $prefix, @completions) = @_;
  $input =~ s/\s+/ /g;

  # Support completion on composite expressions. Hacky, limited syntax support.
  $input =~ s/^[^[]+\[//;
  $input =~ s/^.*;\s*//;

  # If last complete words were options, remove these so we can restart option
  # matching.
  $input =~ s/(?:\s-\w+)+\s((?:-\w+)?)$/ $1/;
  my $word_cnt = () = $input =~ m/\b\s+/g;
  if ($word_cnt == 0) {
    @completions = grep /^\Q$input\E/, @cmds;
  } else {
    my @mmatch = grep /^\Q$input\E/, @multi;
    @completions = map {my @F = split /\s/, $_;
                        $F[$word_cnt]} @mmatch;

    # rlwrap seem to have a 'feature' where words beginning with '-' are
    # prepended with '-', forcing us to remove the dash. Downside is that it
    # will list the options without '-'.
    @completions = map {s/^-//; $_} @completions;
  }

  return @completions;
}
