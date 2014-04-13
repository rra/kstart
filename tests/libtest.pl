# Shared Perl functions for tests.
#
# Collects a set of useful utility functions for tests, used by the Perl test
# suite programs.  These are intentionally put into the main package rather
# than in a separate namespace.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2007, 2008, 2009
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

require 5.006;
use strict;

use Test::More;

# Make a call to a command with the given arguments.  Returns the standard
# output, the standard error, and the exit status as a list.
sub command {
    my ($command, @args) = @_;
    my $pid = fork;
    if (not defined $pid) {
        BAIL_OUT ("cannot fork: $!");
    } elsif ($pid == 0) {
        open (STDOUT, '>', 'command.out')
            or BAIL_OUT ("cannot create command.out: $!");
        open (STDERR, '>', 'command.err')
            or BAIL_OUT ("cannot create command.err: $!");
        exec ($command, @args)
            or BAIL_OUT ("cannot run $command: $!");
    } else {
        waitpid ($pid, 0);
    }
    my $status = ($? >> 8);
    local $/;
    open (OUT, '<', 'command.out') or BAIL_OUT ("cannot open command.out: $!");
    my $output = <OUT>;
    close OUT;
    open (ERR, '<', 'command.err') or BAIL_OUT ("cannot open command.err: $!");
    my $error = <ERR>;
    close ERR;
    unlink ('command.out', 'command.err');
    return ($output, $error, $status);
}

# Returns the one-line contents of a file as a string, removing the newline.
sub contents {
    my ($file) = @_;
    open (FILE, '<', $file) or BAIL_OUT ("cannot open $file: $!");
    my $data = <FILE>;
    close FILE;
    chomp $data;
    return $data;
}

# Given a keytab file, a principal, and additional options for kinit, try
# authenticating with kinit.  This is used to do things like get renewable
# tickets.  Returns true if successful, false otherwise.
sub kinit {
    my ($file, $principal, @opts) = @_;
    my @commands = (
        "kinit -k -t $file @opts $principal ",
        "kinit -t $file @opts $principal ",
        "kinit -T /bin/true -k -K $file @opts $principal",
    );
    for my $command (@commands) {
        if (system ("$command >/dev/null 2>&1 </dev/null") == 0) {
            return 1;
        }
    }
    return 0;
}

# Run klist and return the default principal, the first service principal
# found, and the flags.  Returns both as undef if klist fails.
sub klist {
    my $output = `klist -f -5 2>&1`;
    return unless $? == 0;
    my ($default) = ($output =~ /^(?:Default p|\s*P)rincipal: (\S+)/m);
    my ($service) = ($output =~ / Service principal\n(?:\S+\s+){4}(\S+)/);
    unless ($service) {
        ($service) = ($output =~ / Principal\n(?:\S+\s+){7}(\S+)/);
    }
    my ($flags) = ($output =~ /\sFlags: (\S+)/);
    unless ($flags) {
        ($flags) = ($output =~ / Flags\s+Principal\n(?:\S+\s+){6}(\S+)/);
    }
    return wantarray ? ($default, $service, $flags) : $default;
}

# Run tokens and return true if we have an AFS token, false otherwise.
sub tokens {
    my $output = `tokens 2>&1`;
    return unless $? == 0;
    return ($output =~ /^(User\'s \([^\)]+\) )?[Tt]okens for /m) ? 1 : 0;
}
