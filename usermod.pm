package Linux::usermod;

use strict;
use Carp;
use vars qw($VERSION);
$VERSION = 0.4;

our $file_passwd = '/etc/passwd';
our $file_shadow = '/etc/shadow';
 
my %field = (
	NAME       => 0,	#The user's name
	PPASSWORD  => 1,	#The "passwd" file password
	UID        => 2,	#The user's id
	GID        => 3,	#The user's group id 
	COMMENT    => 4,	#A Comment about the user
	HOME       => 5,	#The user's home directory
	SHELL      => 6,	#The user's shell
	SNAME	   => 7,	#The user's name in shadow file 
	PASSWORD   => 8,	#A 13-character encrypted password.
	LASTCHG	   => 9, 	#The number of days from January 1, 1970 of the last password changed date.
	MIN	   => 10, 	#The minimum number of days required between password changes.
	MAX 	   => 11,	#The maximum number of days the password is valid.
	WARN 	   => 12,	#The number of days before expiring the password that the user is warned.
	INACTIVE   => 13,	#The number of days of inactivity allowed for the user.
	EXPIRE 	   => 14,	#The absolute date after which the login may no longer be used.
	FLAG	   => 15	#Currently not used.	
);

sub fields { keys %field }

sub new {
	my $class = shift;
	my $user = shift;
	(my @args) = _read_user($user, $file_passwd);
	@args =	(@args, _read_user($user, $file_shadow));
	croak "no such user" unless scalar @args > 0;
	return bless [ @args ], ref($class)||$class;
}

sub get {
	my $self = shift;
	my $what = shift;
	return $self->[$what] if $what =~ /^\d$/;
	$what = uc $what;
	return $self->[$field{$what}];
}

sub set {
	my $self = shift;
	my $what = shift;
	$what = uc $what;
	return 0 unless exists($field{$what});
	return 0 unless my $newval = shift;
	return 0 if $newval =~ /:/ and $field{$what} != 8; 
	my $flag = shift || 0;
	my $oldval = $self->[$field{$what}];
	my $name = $self->[$field{NAME}];
	$self->[$field{$what}] = $newval unless $flag;
	if($field{$what} <= 6){
		my @file = _io_file("$file_passwd", '', 'r');
		my @user;
		push @user, $self->[$_] for 0..6;
		my $user = join ':', @user;
		for(@file){ s/.+/$user/ if /^$name:/ }
		_io_file("$file_passwd", \@file, 'w');
		
	}
	if($field{$what} > 6){	
		my @file = _io_file("$file_shadow", '', 'r');
		$self->[9] = _get_1970_diff() if $field{$what} == 8;
		if($field{$what} == 8){
			if($flag =~ /^(l|u)$/){
				if($flag eq 'l'){
					$self->[8] =~ /^!/ or $self->[8] =~ s/(.)/!$1/
				}
				if($flag eq 'u'){
					$self->[8] =~ /^!/ and $self->[8] =~ s/^!(.)/$1/
				}
			}else{
				$self->[8] = _gen_pass($self->[$field{$what}])
			}
		}
		my @user;
		push @user, "$self->[$_]" for 7..15;
		my $user = join ':', @user;
		for(@file){ s/.+/$user/ if /^$name:/ }
		_io_file("$file_shadow", \@file, 'w');
	}	
	return 1
}

sub _read_user {
	my $username = shift;
	my $file = shift;
	my @user;
	local *FH;
	open FH, "$file" or croak "cannot open_r $file";
	while(<FH>){ /^$username:/ and @user = split /:/, $_ and last }
	close FH;
	s/\n// for @user;
	return (@user);
}

sub _gen_pass {
	my $password = shift;
	$password or croak "no password given";
	my @rands = ( "A" .. "Z", "a" .. "z", 0 .. 9 );
	my $salt = join("", @rands[ map { rand @rands } ( 1 .. 8 ) ]);
	return crypt($password, q($1$)."$salt");
}

sub _exists {
	my $username = shift || die "no usrename given";
	(my @fields) = (_read_user($username, $file_passwd));
	return scalar @fields;
}

sub add {
	my $class = shift;
	my (%fields, $c, @args);
	push @args, $_ for @_;
	croak "no username given" if scalar @args == 0;
	croak "user $args[0] exists" if _exists($args[0]);
	for(@args){
		chomp($_);
		/^\s*$/ and $c++ and next;
		$c++;
		if($c == 1){
			croak "wrong username given" if /:/;
			croak "wrong username" unless /^([A-Z]|[a-z]){1}\w{0,254}/;
			$fields{username} = $_ || croak "no username given";
		}
		if($c == 2){
			croak "wrong password length" unless /^(.*){0,254}$/;
			$fields{password} = _gen_pass($_) if $_;
		}
		if($c == 3){
			$_ == '' and $_ = 1000;
		 	croak "wrong uid" unless /^\d+$/;
			croak "wrong uid" if $_ > 65535 or $_ < 1;
			$fields{uid} = $_ || 1000;
		}
		if($c == 4){
			$_ == '' and $_ = 1000;
			croak "wrong gid" unless /^\d+$/;
			if(/^\d+$/){ croak "wrong gid" if $_ > 65535 or $_ < 1 }
			$fields{gid} = $_ || $fields{uid};
		}
		if($c == 5){
			croak "wrong comment given" if /:/;
			$fields{comment} = $_;
		}
		if($c == 6){
			croak "wrong home given" if /:/;
			$fields{home} = $_;
		}
		if($c == 7){
			croak " wrong shell given" if /:/;
			$fields{shell} = $_;
		}
	}
	$fields{password} or $fields{password} = '!';
	my @file = _io_file("$file_passwd", '', 'r');
	my @ids;
	push @ids, (split /:/)[2] for @file;
	for(@ids){ $fields{uid} = 1000 and last if $fields{uid} == $_ }
	if($fields{uid} == 1000){
	   for(sort @ids){ 
		$_ < 1000 and next;
		$fields{uid} == $_ and $fields{uid}++;
	   }
	}
	$fields{gid} = $fields{uid} if !$fields{gid};
	my @newuser = ("$fields{username}:x:$fields{uid}:$fields{gid}:$fields{comment}:$fields{home}:$fields{shell}");
	_io_file("$file_passwd", \@newuser, 'a');
	my $time_1970 = _get_1970_diff();
	@newuser = ("$fields{username}:$fields{password}:$time_1970:0:99999:7:::");
	_io_file("$file_shadow", \@newuser, 'a');
	return 1
}

sub del{
	my $class = shift;
	my $username = shift;
	_exists($username) or croak "$username does not exist";
	my @old = _io_file("$file_passwd", '', 'r');
	my @new;
	/^$username:/ or push @new, $_ for @old;
	_io_file("$file_passwd", \@new, 'w');
	@new = ();
	@old = _io_file("$file_shadow", '', 'r');
	/^$username:/ or push @new, $_ for @old;
	_io_file("$file_shadow", \@new, 'w');
	return 1
	
}

sub _io_file{
	no strict;
        my $file = shift;
	my $ref_f = shift;
	my $flag = shift;
	croak $! unless -f $file;
	croak "posible flags: r/w/a" unless $flag =~ /^(r|w|a)$/;
	if($flag eq 'r'){
		@{$ref_f} = ();
		local *FH;
		open FH, $file or croak "cannot open_r $file";
		flock FH, 1;
		$_ =~ s/\n// and push @{$ref_f}, $_ while <FH>;
		close FH;
		return @{$ref_f}
	}
	if($flag eq 'w'){
		local *FH;
		open FH, "> $file" or croak "cannot open_w $file";
		flock FH, 2;
		print FH "$_\n" for @{$ref_f};
		close FH;
		return 1
	}
	if($flag eq 'a'){
		local *FH;
		open FH, ">> $file" or croak "cannot open_a $file";
		flock FH, 2;
		print FH "$_\n" for @{$ref_f};
		close FH;
		return 1
	}
}
	
sub lock{
	my $self = shift;
	$self->set('password', 'block', 'l');
}

sub unlock{
        my $self = shift;
        $self->set('password', 'block', 'u');
}

sub _get_1970_diff{ return int time / (3600 * 24) }

1

__END__

=head1 NAME

Linux::usermod - modify user accounts

=head1 SYNOPSIS

use Linux::usermod;

$user = Linux::usermod->new(username);

#all fields are returned from the class method fields

$user->get(gid); #or the same $user->get(3);
$user->get(uid); #the same $user->get(2);
$user->get(shell); #the same $user->get(6);
$user->get(ppassword); #passwd file 
$user->get(password); #shadow file - the encoded password

$user->set(password); 
$user->set(shell);

Linux::usermod->add(username);

#or

Linux::usermod->add(username, password, uid, gid, comment, home, shell);

#where the password goes in shadow file and gid becomes equal to uid unless specified
#and uid is becoming the first unreserved number after 1000 unless specified

Linux::usermod->del(username);

print $user->get($_) for (Linux::usermod->fields);

=head1 DESCRIPTION

B<Linux::usermod> which adds, removes and modify user account according to 
the passwd and shadow files syntax (like struct passwd from pwd.h). It is not necessary 
those accounts to be system as long as Linux::usermod::file_passwd and Linux::usermod::file_shadow 
are not in "/etc" directory.

=head1 METHODS

=over 4

=item B<new> (username)

=item B<add> (username, ...)

Class method - add new user account
arguments to add are optional, except username;
they may be (username, password, uid, gid, comment, home, shell)

=item B<del> (username)

Class method - removes user account

=item B<get> get one of the following fields:
	
=over 4

=item B<NAME>		
or 0  - The user's name

=item B<PPASSWORD> 	
or 1  - The "passwd" file password

=item B<UID>		
or 2  - The user's id

=item B<GID>		
or 3  - The user's group id

=item B<COMMENT>	
or 4  - The Comment about the user (real username)

=item B<HOME>		
or 5  - The user's home directory

=item B<SHELL>		
or 6  - The user's shell

=item B<SNAME>		
or 7  - The user's name in shadow file

=item B<PASSWORD>	
or 8  - The 13-character encoded password

=item B<LASTCHG>	
or 9  - The number of days from January 1, 1970 of the last password changed date

=item B<MIN>		
or 10 - The minimum number of days required between password changes

=item B<MAX>		
or 11 - The maximum number of days the password is valid

=item B<WARN>		
or 12 - The number of days before expiring the password that the user is warned

=item B<INACTIVE>	
or 13 - The number of days of inactivity allowed for the user

=item B<EXPIRE>		
or 14 - The absolute date after which the login may no longer be used

=item B<FLAG>		
or 15 - Currently not used

=back

either string or number can be argument

=item B<set> (field) 

set a field which must be string, but not a number

=item B<lock> (username)

Lock user account (puts '!' at the beginning of the encoded password)

=item B<unlock>

Unlock user account (removes '!' from the beginning of the encoded password)

=head1 FILES

B</etc/passwd>, B</etc/shadow> unless given your own B<passwd> and B<shadow> files
which must be created no matter what their names are as long as Linux::usermod::file_passwd
and Linux::usermod::file_shadow vars know about them

=head1 SEE ALSO

B<getpwent>(3), B<getpwnam>(3), B<usermod>(8), B<passwd>(8)

=head1 BUGS

None known. Report any to author.

=head1 AUTHOR

Vidul Petrov, vidul@abv.bg

� 2004 Vidul Petrov. All rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.


=cut








 



