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

use strict;
use warnings;

use bytes;
use integer;

package SMB::Client;

use parent 'SMB';

use IO::Socket;

sub new ($$%) {
	my $class = shift;
	my $share_uri = shift;
	my %options = @_;

	my $self = $class->SUPER::new(
		id      => 0,
		quiet   => delete $options{quiet} || 0,
		verbose => delete $options{verbose} || 0,
		cwd     => '',
	);

	return $self->init($share_uri, %options);
}

sub init ($$%) {
	my $self = shift;
	my $share_uri = shift;
	my %options = @_;

	$options{id} ? $self->{id} = $options{id} : $self->{id}++;

	my ($addr, $share) = $share_uri =~ m![/\\]!
		? $self->parse_share_uri($share_uri)
		: ($share_uri);
	die "Please specify share uri //server.name.or.ip[:port]/share or server.name.or.ip[:port]\n"
		unless $addr;
	$addr .= ':445' unless $addr =~ /:/;

	my $socket = IO::Socket::INET->new(PeerAddr => $addr, Proto => 'tcp')
		or	die "Can't open $addr: $!\n";

	$self->{socket}   = $socket;
	$self->{tree}     = undef;
	$self->{addr}     = $addr;
	$self->{share}    = $share;
	$self->{username} = $options{username};
	$self->{password} = $options{password};

	$self->msg("SMB client #$self->{id} created for server $addr" . (defined $share ? " share $share" : ''));

	return $self;
}

sub connect ($%) {
	my $self = shift;
	my %options = @_;

	my $username = $self->{username} || $options{username} || die "No username to connect\n";
	my $password = $self->{password} || $options{password} || die "No password to connect\n";

	return;
}

sub send_nbss ($$) {
	my $self = shift;
	my $data = shift;

	$self->mem($data, "-> NetBIOS Packet");

	my $size = length($data);
	if (!$self->socket->write($data, $size)) {
		$self->err("Can't write full packet");
		return;
	}
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
