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

package SMB::Proxy;

use parent 'SMB::Server';

use SMB::Client;

use IO::Socket;

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my %client_options = map { $_ => $options{$_} }
		qw(server_addr server_username server_password quiet verbose);

	my $self = $class->SUPER::new(
		%options,
		share_roots    => '-',
		client_options => \%client_options,
	);

	return $self;
}

# on connection from client, create connection to server
sub on_connect ($$) {
	my $self = shift;
	my $connection = shift;

	my %options = %{$self->{client_options}};
	my $client = SMB::Client->new(
		$options{server_addr},
		username => $options{server_username},
		password => $options{server_password},
		quiet    => $options{quiet},
		verbose  => $options{verbose},
	);

	my $connection2 = $self->add_connection($client->socket, -$self->client_id);

	$connection->{connection2} = $connection2;
	$connection2->{connection2} = $connection;
}

# on disconnection from client or server, disconnect the other end
sub on_disconnect ($$) {
	my $self = shift;
	my $connection = shift;

	$self->delete_connection($connection->connection2);
}

# just forward packet to the other end, ignore the actual command semantics
sub recv_command ($$) {
	my $self = shift;
	my $connection = shift;

	$connection->recv_nbss or return;
	$connection->connection2->send_nbss($connection->parser->data);

	return "dummy";
}

sub on_command ($$$) {
	my $self = shift;
	my $connection = shift;
	my $command = shift;

	# ignore a dummy command
}

1;
