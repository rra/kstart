# $Id$
#
# Shared Perl functions for tests.
#
# Collects a set of useful utility functions for tests, used by the Perl test
# suite programs.  These are intentionally put into the main package rather
# than in a separate namespace.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

require 5.006;
use strict;

# Make a call to a command with the given arguments.  Returns the standard
# output, the standard error, and the exit status as a list.
sub command {
    my ($command, @args) = @_;
    my $pid = fork;
    if (not defined $pid) {
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDOUT, '>', 'command.out')
            or die "cannot create command.out: $!\n";
        open (STDERR, '>', 'command.err')
            or die "cannot create command.err: $!\n";
        exec ($command, @args)
            or die "cannot run $command: $!\n";
    } else {
        waitpid ($pid, 0);
    }
    my $status = ($? >> 8);
    local $/;
    open (OUT, '<', 'command.out') or die "cannot open command.out: $!\n";
    my $output = <OUT>;
    close OUT;
    open (ERR, '<', 'command.err') or die "cannot open command.err: $!\n";
    my $error = <ERR>;
    close ERR;
    unlink ('command.out', 'command.err');
    return ($output, $error, $status);
}

# Run klist -5 and return the default principal and the first service
# principal found.  Returns both as undef if klist fails.
sub klist {
    my $output = `klist -5 2>&1`;
    return unless $? == 0;
    my ($default) = ($output =~ /^Default principal: (\S+)/m);
    my ($service) = ($output =~ /Service principal\n(?:\S+\s+){4}(\S+)/);
    return ($default, $service);
}

# Returns the one-line contents of a file as a string, removing the newline.
sub contents {
    my ($file) = @_;
    open (FILE, '<', $file) or die "cannot open $file: $!\n";
    my $data = <FILE>;
    close FILE;
    chomp $data;
    return $data;
}
