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

package SMB::Server;

use strict;
use warnings;

use parent 'SMB';

use IO::Socket;
use IO::Select;
use File::Basename qw(basename);
use SMB::Connection;
use SMB::Tree;
use SMB::v2::Command::Negotiate;

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my $share_roots = delete $options{share_roots};

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

	if (!$share_roots && $FindBin::Bin) {
		my $shares_dir = "$FindBin::Bin/../shares";
		$share_roots = { map { basename($_) => $_ } grep { -d $_ && -x _ && -r _ } glob("$shares_dir/*") }
			if -d $shares_dir;
	}
	unless ($share_roots) {
		$self->err("No share_roots specified and no shares/ autodetected");
		$share_roots = {};
	} elsif (ref($share_roots) ne 'HASH') {
		$self->err("Invalid share_roots ($share_roots) specified");
		$share_roots = {};
	} elsif (!%$share_roots) {
		$self->err("No shares to manage, specify non-empty share_roots hash");
	}
	$self->{share_roots} = $share_roots;

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

	if ($command->is_smb2) {
		my $error = 0;
		if ($command->is('SessionSetup')) {
			$command->header->{uid} = $connection->id;
		}
		elsif ($command->is('TreeConnect')) {
			my ($addr, $share) = $self->parse_share_uri($command->get_uri);
			my $tree_root = $self->share_roots->{$share};
			if ($tree_root || $share eq 'IPC$') {
				my $tid = $command->header->{tid} = @{$connection->{trees} ||= []} + 1;
				push @{$connection->{trees}}, SMB::Tree->new($share, $tid, root => $tree_root);
			} else {
				$error = SMB::STATUS_BAD_NETWORK_NAME;
			}
		}
		$command->prepare_response;
		$command->set_status($error) if $error;
		$connection->send_command($command);
		return;
	}

	$self->msg("Command $command ignored; missing functionality");
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
