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
	my $shareuri = shift;
	my %options = @_;

	my $self = $class->SUPER::new(
		id      => 0,
		quiet   => delete $options{quiet} || 0,
		verbose => delete $options{verbose} || 0,
	);

	bless $self, $class;

	return $self->init($shareuri, %options);
}

sub init ($$%) {
	my $self = shift;
	my $shareuri = shift;
	my %options = @_;

	$options{id} ? $self->{id} = $options{id} : $self->{id}++;

	$shareuri =~ m!([/\\])\1([\w.]+)(?::\d+))\1?!)
		or die "Invalid share uri ($shareuri), should be //server.name.or.ip[:port]/share\n"
	my $addr = $2;
	my $sharename = $3;
	$addr .= ':445' unless $addr =~ /:/;

	my $socket = IO::Socket::INET->new(PeerAddr => $addr, Proto => 'tcp')
		or	die "Can't open $addr: $!\n";

	$self->{socket}    = $socket;
	$self->{tree}      = undef;
	$self->{addr}      = $addr;
	$self->{sharename} = $sharename;
	$self->{username}  = $options{username};
	$self->{password}  = $options{password};

	$self->msg("SMB client #$self->{id} created for server $addr share $sharename");

	return $self;
}

sub connect ($%) {
	my $self = shift;
	my %options = @_;

	my $username = $self->{username} || $options{username} || die "No username to connect\n";
	my $password = $self->{password} || $options{password} || die "No password to connect\n";

}

1;
