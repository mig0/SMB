# SMB Perl library, Copyright (C) 2014 Mikhael Goikhman, migo@cpan.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

package SMB::Client;

use strict;
use warnings;

use parent 'SMB::Agent';

use IO::Socket;

sub new ($$%) {
	my $class = shift;
	my $share_uri = shift;
	my %options = @_;

	my $quiet   = delete $options{quiet}   || 0;
	my $verbose = delete $options{verbose} || 0;

	my $self = $class->SUPER::new(
		%options,
		cwd       => '',
		server_id => 0,  # running index
	);

	$self->connect($share_uri, %options)
		if $share_uri;

	return $self;
}

sub connect ($$%) {
	my $self = shift;
	my $share_uri = shift;
	my %options = @_;

	my ($addr, $share) = $share_uri =~ m![/\\]!
		? $self->parse_share_uri($share_uri)
		: ($share_uri);
	die "Please specify share uri //server.name.or.ip[:port]/share or server.name.or.ip[:port]\n"
		unless $addr;
	$addr .= ':445' unless $addr =~ /:/;

	my $socket = IO::Socket::INET->new(PeerAddr => $addr, Proto => 'tcp')
		or	die "Can't open $addr: $!\n";

	if ($options{just_socket}) {
		$self->{socket} = $socket;
	} else {
		$self->add_connection(
			$socket, --$self->{server_id},
			addr     => $addr,
			share    => $share,
			username => $options{username},
			password => $options{password},
			tree     => undef,
			openfiles => {},
		);
	}

	return $self;
}

sub connect_tree ($%) {
	my $self = shift;
	my %options = @_;

	my $username = $self->{username} || $options{username} || die "No username to connect\n";
	my $password = $self->{password} || $options{password} || die "No password to connect\n";

	return;
}

sub normalize_path ($$) {
	my $self = shift;
	my $path = shift // '';

	$path = "$self->{cwd}/$path" if $path =~ m!^[^/]!;

	# TODO: strip "subdir/.." parts
	$path =~ s!/+$!/!g;
	$path =~ s!/$!!;

	return $path;
}

sub chdir ($$) {
	my $self = shift;
	my $dir = shift // '';

	$self->{cwd} = $self->normalize_path($dir);
}

1;
