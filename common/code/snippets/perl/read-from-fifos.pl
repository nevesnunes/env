#!/usr/bin/perl

use threads;
use threads::shared;
use Thread::Queue;

my $done :shared;

my $DataQueue = Thread::Queue->new();

my @producers;
for (@ARGV) {
    push @producers, threads->create('producer', $_);
}

while($done <= $#ARGV) {
    # This blocks until $DataQueue->pending > 0
    print $DataQueue->dequeue();
}

for (@producers) {
    $_->join();
}


sub producer {
    open(my $fh, "<", shift) || die;
    while(<$fh>) {
        $DataQueue->enqueue($_);
    }
    # Closing $fh blocks
    # close $fh;
    $done++;
    # Guard against race condition
    $DataQueue->enqueue("");
}
