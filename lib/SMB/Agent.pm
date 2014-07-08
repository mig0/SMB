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

package SMB::Agent;

use strict;
use warnings;

use parent 'SMB';

use SMB::Connection;
use IO::Socket;
use IO::Select;

sub new ($%) {
	my $class = shift;
	my %options = @_;

	$options{quiet}   ||= 0;
	$options{verbose} ||= 0;

	my $self = $class->SUPER::new(
		%options,
		socket_pool => IO::Select->new,
		connections => {},
	);

	return $self;
}

sub add_connection ($$$%) {
	my $self = shift;
	my $socket = shift;
	my $id = shift;
	my %options = @_;

	my $connection = SMB::Connection->new(
		$socket, $id,
		quiet     => $self->quiet,
		verbose   => $self->verbose,
		%options,
	) or return;
	$self->socket_pool->add($socket);
	$self->connections->{$socket->fileno} = $connection;

	return $connection;
}

sub delete_connection ($$) {
	my $self = shift;
	my $connection = shift;

	my $socket = $connection->socket;
	$self->socket_pool->remove($socket);
	delete $self->connections->{$socket->fileno};
	$connection->close;
}

1;