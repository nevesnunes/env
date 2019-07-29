#! /usr/bin/perl

use strict;
use warnings;

use Font::TTF::Font;

die "Usage: $0 font.ttf...\n" unless @ARGV;

foreach my $filename (@ARGV) {
  (my $backup = $filename) =~ s/\.[^.]+$/.bak/
    or die "$0: $filename does not have an extension\n";

  my $f = Font::TTF::Font->open($filename)
    or die "$0: unable to read $filename\n";

  $f->{hhea}->read;
  # $f->{hhea}{Ascender} = 1884;
  # $f->{hhea}{Descender} = 514;
  $f->{hhea}{LineGap} = 0;

  rename $filename, $backup
    or die "$0: can't rename $filename to $backup ($!)\n";

  $f->out($filename)
    or die "$0: can't write $filename\n";
}
