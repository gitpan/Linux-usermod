use strict;
use Test;

BEGIN { plan tests => 5 }

use Linux::usermod;

my $tester = Linux::usermod->new("root");
ok($tester) or warn "user object creation failed\n";
my @user = getpwnam("root");
ok($user[2], $tester->show("uid")) or warn "\tuid field unrecognized\n";
ok($user[3], $tester->show("gid")) or warn "\tgid field unrecognized\n";
ok($user[7], $tester->show("home")) or warn "\thome field unrecognized\n";
my $shell = $tester->show("shell");
chomp($shell);
ok($user[8], $shell) or warn "\tshell  field unrecognized\n";
