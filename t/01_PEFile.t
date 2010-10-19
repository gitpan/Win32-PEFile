use strict;
use warnings;

use Test::More tests => 9;

use constant kTestFile => 'PEFile.exe';
use constant kBadFile => '01_PEFile.t';

=head1 NAME

Win32::PEFile test suite

=head1 DESCRIPTION

This file contains an install test suite to be run on a target system as a
check that the Win32::PEFile module works correctly with the target system.

See tests in the ../xt folder for more comprehensive release tests.

=cut

BEGIN {
    use lib '../lib';    # For development testing
    use_ok ("Win32::PEFile");
}

ok (my $pe = Win32::PEFile->new (-file => kTestFile),
    'Create Win32::PEFile instance');
ok ($pe->isOk (), "Ok set for PE file");
is ($pe->getEntryPoint ('EntryPoint1'), '1', 'Find EntryPoint1');
is ($pe->getEntryPoint ('EntryPoint2'), '',  "Don't find EntryPoint2");

my $strs = $pe->getVersionStrings ();
is ($strs->{'ProductName'}, 'PEFile Application', "Get Product name");
is ($strs->{'ProductVersion'}, '1, 0, 0, 1', "Get Product version");

$pe = Win32::PEFile->new (-file => kBadFile);
ok (! $pe->isOk (), "Not ok for non-PE file");
is ($pe->lastError (), <<ERROR, "lastError set for non-PE file");
Error in PE file 01_PEFile.t: No MZ header found

ERROR


sub mustDie {
    my ($test, $errMsg, $name) = @_;

    eval {$test->();};
    my $err = $@;
    my $isRightFail = defined ($err) && $err =~ /\Q$errMsg\E/;

    print defined $err ? "Error: $err\n" : "Unexpected success. Expected: $errMsg\n"
        if !$isRightFail;
    ok ($isRightFail, $name);
}
