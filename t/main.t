use strict;
use Test;

BEGIN { plan tests => 7 }

use Linux::usermod;

my $passwd = "t/passwd";
my $shadow = "t/shadow";
my $user = "tester";
my $uid = "65000";
my $gid = "65000";
my $comment = "tester account";
my $home = "./";
my $shell = "/dev/null";

open FH, ">$passwd" or die "can't open $passwd";
close FH;
open FH, ">$shadow" or die "can't open $shadow";
close FH;

$Linux::usermod::file_passwd = $passwd;
$Linux::usermod::file_shadow = $shadow;

Linux::usermod->add($user, "", $uid, $gid, $comment, $home, $shell);

my $tester = Linux::usermod->new($user);

ok($tester) or warn "user object creation failed\n";
ok($user, $tester->get("name")) or warn "\tname field unrecognized\n";
ok($uid, $tester->get("uid")) or warn "\tuid field unrecognized\n";
ok($gid, $tester->get("gid")) or warn "\tgid field unrecognized\n";
ok($comment, $tester->get("comment")) or warn "\tcomment field unrecognized\n";
ok($home, $tester->get("home")) or warn "\thome field unrecognized\n";
ok($shell, $tester->get("shell")) or warn "\tshell field unrecognized\n";
