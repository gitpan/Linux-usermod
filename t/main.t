use strict;
use Test;

BEGIN { plan tests => 5 }

use Linux::usermod;

my $tester = Linux::usermod->new("root");
ok($tester) or warn "user object creation failed\n";
my @user = getpwnam("root");
ok($user[0], $tester->get("name")) or warn "\tname field unrecognized\n";
ok($user[2], $tester->get("uid")) or warn "\tuid field unrecognized\n";
ok($user[3], $tester->get("gid")) or warn "\tgid field unrecognized\n";
ok($user[8], $tester->get("shell")) or warn "\tshell field unrecognized\n";
