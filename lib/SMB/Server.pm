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

package SMB::Server;

use parent 'SMB';

use IO::Socket;
use IO::Select;
use SMB::Connection;
#use SMB::Commands;
use SMB::v2::Command::Negotiate;

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my $port = delete $options{port};
	my $fifo_filename = delete $options{fifo_filename};

	die "Neither port nor fifo-filename is specified for server\n"
		unless $port || $fifo_filename;

	my $main_socket = $fifo_filename
		? IO::Socket::UNIX->new(Listen => 1, Local => $fifo_filename)
		: IO::Socket::INET->new(Listen => 1, LocalPort => $port, Reuse => 1);

	my $listen_label = $fifo_filename ? "fifo $fifo_filename" : "port $port";
	die "Can't open $listen_label: $!\n" unless $main_socket;

	my $self = $class->SUPER::new(
		%options,
		main_socket => $main_socket,
		socket_pool => IO::Select->new($main_socket),
		connections => {},
		client_id => 0,  # running index
	);

	bless $self, $class;

	$self->msg("SMB server started, listening on $listen_label");

	return $self;
}

sub on_command ($$$) {
	my $self = shift;
	my $connection = shift;
	my $command = shift;

	if ($command->is_smb1) {
		if ($command->is('Negotiate') && $command->supports_protocol(2)) {
			$command = SMB::v2::Command::Negotiate->new_from_v1($command);
		}
	}

	$connection->msg("Got command $command, ignoring");
}

sub run ($) {
	my $self = shift;

	my $socket_pool = $self->socket_pool;
	my $connections = $self->connections;

	while (my @ready_sockets = $socket_pool->can_read) {
		foreach my $socket (@ready_sockets) {
			if ($socket == $self->main_socket) {
				my $client_socket = $socket->accept || next;
				$socket_pool->add($client_socket);
				my $connection = SMB::Connection->new($client_socket, ++$self->{client_id}, quiet => $self->{quiet});
				unless ($connection) {
					$socket->close;
					next;
				}
				$connections->{$client_socket->fileno} = $connection;
			}
			else {
				my $fd = $socket->fileno;
				my $connection = $connections->{$fd} || die "Unexpected data on unexisting fd $fd";
				my $command = $connection->recv_command;
				if (!$command) {
					$socket_pool->remove($socket);
					delete $connections->{$fd};
					next;
				}
				$self->on_command($connection, $command);
			}
		}
	}
}

1;
