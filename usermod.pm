package Linux::usermod;

use strict;
use Carp;
use vars qw($VERSION);
$VERSION = 0.3;



sub new {
	my ($pkg, $name) = @_;
	my $usr = bless {
		"name" => $name,
	}, $pkg;
	return $usr;
}

sub show {
	my($usr, $field) = @_;
	return $usr->change($field);
}
sub change {
	my($usr, $field, $new_value, $salt) = @_;
	my($fields, @fields, $file, @F);
	my $username = $usr->{"name"};
	$salt = $salt ? $salt : "13";
	if (defined($new_value) && $new_value !~ /^([!-\/\w\s+"]*)$/) { carp "Malicious data in new value"; }
 if($field eq "uid" || $field eq "gid" || $field eq "comment" || $field eq "home" || $field eq "shell") {
	my $file = "/etc/passwd";
	if (defined($new_value)) {
		open(FH, "+<$file") or croak "cannot open /etc/passwd\n";
		flock(FH, 2) or croak "cannot lock /etc/passwd\n";
		@F = <FH>;
		for (@F) {
			if(/^$username:/){
				@fields = split(/:/, $_, 7);
				CASE: {
				 if($field eq "uid") { 
					$usr->{"uid"} = 
					($fields[2] = $new_value ? $new_value : $fields[2]); 
					last CASE }
				 if($field eq "gid") { $usr->{"gid"} = 
					($fields[3] = $new_value ? $new_value : $fields[3]); 
					last CASE }
				 if($field eq "comment") { $usr->{"comment"} = 
					($fields[4] = $new_value ? $new_value : $fields[4]); 
					last CASE }
				 if($field eq "home") { $usr->{"home"} = 
					($fields[5] = $new_value ? $new_value : $fields[5]); 
					last CASE }
				 if($field eq "shell") { $usr->{"shell"} = 
					($fields[6] = $new_value ? $new_value : $fields[6]); 
					last CASE }
				}
			$fields = join(":", @fields);
			$fields =~ s/\n//
			}
		}
	for(@F) { if(/^$username:/){  s/.*/$fields/; } }
	seek(FH, 0, 0) or croak "cannot seek passwd file\n";
	print FH @F or croak "cannot write to passwd file\n";
	truncate(FH, tell(FH)) or croak "cannot truncate passwd file\n";
	close(FH);
	return $usr->{$field};
	} else {
		open(FH, "<$file") or croak "cannot open /etc/passwd\n";
		flock(FH, 1) or croak "cannot lock /etc/passwd\n";
		@F = <FH>;
		for (@F) {
	         if(/^$username:/){
			@fields = split(/:/, $_, 7);
			$usr->{"uid"} = $fields[2];
			$usr->{"gid"} = $fields[3];
			$usr->{"comment"} = $fields[4];
			$usr->{"home"} = $fields[5];
			$usr->{"shell"} = $fields[6];
		 }
		}
		close(FH);
		return $usr->{$field};
	}
 } elsif($field eq "password" || $field eq "password_l" || $field eq "password_u" ||
	 $field eq "dsalch" || $field eq "may" || $field eq "must" || 
	 $field eq "warn" || $field eq "expire" || $field eq "dsdis") {
	my $file = "/etc/shadow";
	open(FH, "+<$file") or croak "cannot open /etc/shadow\n";
	flock(FH, 2) or croak "cannot lock /etc/shadow\n";
	@F = <FH>;
	for (@F) {
		if(/^$username:/){
	  		@fields = split(/:/, $_, 8);
			CASE: {
				if($field eq "password") {
					if($fields[1] =~ /^!/) { 
					  $fields[1] =~ s/^!//;
					  ($fields[1] = $new_value ?
					  crypt($new_value, substr($fields[1], 0, $salt))
					  : $fields[1]) =~ s/(.*)/!$1/;
					  $usr->{"password"} = $fields[1];
					} else { 
					  $usr->{"password"} = ($fields[1] = $new_value ?
				  	  crypt($new_value, substr($fields[1], 0, $salt)) : $fields[1]);
					}
					last CASE
				}
				if($field eq "password_l") { 
					($fields[1] =~ s/(.*)/!$1/) if($fields[1] !~ /^!/);
					last CASE
				}
				if($field eq "password_u") { 
					($fields[1] =~ s/^!//) if($fields[1] =~ /^!/);
					last CASE
				}  
				if($field eq "dsalch") { $usr->{"dsalch"} = 
					($fields[2] = $new_value ? $new_value : $fields[2]); 
					last CASE }
				if($field eq "may") { $usr->{"may"} = 
					($fields[3] = $new_value ? $new_value : $fields[3]); 
					last CASE }
				if($field eq "must") { $usr->{"must"} = 
					($fields[4] = $new_value ? $new_value : $fields[4]); 
					last CASE }
				if($field eq "warn") { $usr->{"warn"} = 
					($fields[5] = $new_value ? $new_value : $fields[5]);
					 last CASE }
				if($field eq "expire") { $usr->{"expire"} =
					($fields[6] = $new_value ? $new_value : $fields[6]);
					 last CASE }
				if($field eq "dsadis") { $usr->{"dsadis"} = 
					($fields[7] = $new_value ? $new_value : $fields[7]);
					 last CASE }
			}
			$fields = join(":", @fields);
			$fields =~ s/\n//;
		}
	}
	for(@F) { if(/^$username:/){ s/.*/$fields/ } }
	seek(FH, 0, 0) or croak "cannot seek shadow file\n";
	print FH @F or croak "cannot write to shadow file\n";
	truncate(FH, tell(FH)) or croak "cannot truncate shadow file\n";
	close(FH);
	return $usr->{$field};
 } elsif($field eq "name") {
	my $sfile = "/etc/shadow";
	my $pfile = "/etc/passwd";
	if(!$new_value) {
		open(FH, "<$pfile") or croak "cannot open /etc/passwd\n";
		flock(FH, 2) or croak "cannot lock /etc/passwd\n";
		@F = <FH>;
		close(FH);
		for(@F) {
		 if(/^\Q$username\E:/){
			return $username;
		 }
		}
	} else {
		open(FH, "<$pfile") or croak "cannot open /etc/passwd\n";
		flock(FH, 2) or croak "cannot lock /etc/passwd\n";
		@F = <FH>;
		close(FH);
		for(@F) {
			if(/^\Q$new_value\E:/) {
				croak "username already in use\n"
			}
		}
	}
	open(FH, "+<$pfile") or croak "cannot open /etc/passwd\n";
	flock(FH, 2) or croak "cannot lock /etc/passwd\n";
	@F = <FH>;
	for (@F) {
		if(/^$username:/){
			@fields = split(/:/, $_);
			$usr->{"name"} = ($fields[0] = $new_value ? $new_value : $fields[0]);
			$fields = join(":", @fields);
			$fields =~ s/\n//
			}
	}
	for(@F) { if(/^$username:/){  s/.*/$fields/; } }
	seek(FH, 0, 0) or croak "cannot seek passwd file\n";
	print FH @F or croak "cannot write to passwd file\n";
	truncate(FH, tell(FH)) or croak "cannot truncate passwd file\n";
	close(FH);
	open(FH, "+<$sfile") or croak "cannot open /etc/shadow\n";
	flock(FH, 2) or croak "cannot lock /etc/shadow\n";
	@F = <FH>;
	for(@F) {
	   if($_ =~ /^\Q$new_value\E^:/) {
		croak "name already in use\n";
	   }
	}

	for (@F) {
		if(/^$username:/){
			@fields = split(/:/, $_);
			$fields[0] = $new_value ? $new_value : $fields[0];
			}
			$fields = join(":", @fields);
			$fields =~ s/\n//;
	}
	for(@F) { if(/^$username:/){ s/.*/$fields/ } }
	seek(FH, 0, 0) or croak "cannot seek shadow file\n";
	print FH @F or croak "cannot write to shadow file\n";
	truncate(FH, tell(FH)) or croak "cannot truncate shadow file\n";
	close(FH);
	return $usr->{"name"};
 } else { return "Illegal field name!\n" }
}
sub lock {
	my($usr) = shift;
	$usr->change("password_l");
	return $usr->change("password");
}
sub unlock {
	my($usr) = shift;
	$usr->change("password_u");
	return $usr->change("password");
}
sub authors {
	my $pkg = shift;
	print "Thanks to the authors of Perl and Linux!\n"
}

1;

__END__

=head1 NAME

Linux::usermod - modify user accounts

=head1 SYNOPSIS

  use Linux::usermod;

  $user = Linux::usermod->new("username");

  $user->change($field_name, $new_value);
  $user->show($field_name);
  $user->lock;
  $user->unlock;

=head1 DESCRIPTION

B<Linux::usermod> is a simple package which change or return fields from B</etc/passwd> and B</etc/shadow>
files. It acts like  B<usermod> (with the main exception it is OOPerl program).
The job is done entirely in B<change> which returns(B<show>s) the value of the field specified as a first argument. The second optional argument serves as a new value for the field. If password field is specified, You
can use third argument for the value of B<salt> which is 13 characters by default. The package implements a
simple taint checking by 'carping'(warning) for input data which is not any of the following: '!-\/\w\s+"'.

=head1 METHODS

=over 4

=item B<change> method - B<fields> take the following values:


=over 4

=item B<comment> -
comments or user full name

=item B<dsadis> -
days since Jan 1, 1970 that account is disabled

=item B<dsalch> -
days since Jan 1, 1970 that password was last changed

=item B<expire> -
days after password expired that account is disabled

=item B<gid> -
group id

=item B<home> -
home directory

=item B<may> -
days before password may be changed

=item B<must> -
days after which password must be changed

=item B<name> -
username

=item B<password> -
encoded password from shadow file

=item B<shell> -
login shell

=item B<uid> -
user id

=item B<warn> -
days before password is to expire user is warned

=back

=item B<show>

returns the field specified as its only argument. Equivalent to
B<change> when one argument is given.

=item B<lock>

Lock a user account ('!' at the beginning of the encoded password)

=item B<unlock> 

Unlock user account (removes '!' from the beginning of the encoded
password)

=back

=head1 FILES

B</etc/passwd>, B</etc/shadow>

=head1 SEE ALSO 

B<getpwent>(3), B<getpwnam>(3), B<usermod>(8), B<passwd>(8)

=head1 AUTHOR

Vidul Petrov, vidul@abv.bg
don't forget the method B<authors> :)

=head1 COPYRIGHT

© 2002 Vidul Petrov. All rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.


=cut
