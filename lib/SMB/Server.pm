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
use SMB::v2::Command::Create;

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my $share_roots = delete $options{share_roots};

	my $port = delete $options{port};
	my $fifo_filename = delete $options{fifo_filename};

	die "Neither port nor fifo-filename is specified for $class\n"
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
	} elsif (ref($share_roots) eq '' && $share_roots eq '-') {
		# special syntax to request a share-less server, don't complain
		$share_roots = {};
	} elsif (ref($share_roots) ne 'HASH') {
		$self->err("Invalid share_roots ($share_roots) specified");
		$share_roots = {};
	} elsif (!%$share_roots) {
		$self->err("No shares to manage, specify non-empty share_roots hash");
	}
	$self->{share_roots} = $share_roots;

	$self->msg("$class started, listening on $listen_label");

	return $self;
}

sub add_connection ($$$) {
	my $self = shift;
	my $socket = shift;
	my $id = shift;

	my $connection = SMB::Connection->new($socket, $id, quiet => $self->{quiet}) or return;
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

sub on_connect ($$) {
	my $self = shift;
	my $connection = shift;

	# intended to be overriden in sub-classes
}

sub on_disconnect ($$) {
	my $self = shift;
	my $connection = shift;

	# intended to be overriden in sub-classes
}

sub recv_command ($$) {
	my $self = shift;
	my $connection = shift;

	return $connection->recv_command;
}

sub on_command ($$$) {
	my $self = shift;
	my $connection = shift;
	my $command = shift;

	my $tid = $command->header->{tid};
	my $tree = $tid ? (grep { $_->id == $tid } @{$connection->{trees}})[0] : undef;
	$command->{tree} = $tree if $tree;

	if ($command->is_smb1) {
		if ($command->is('Negotiate') && $command->supports_protocol(2)) {
			$command = SMB::v2::Command::Negotiate->new_from_v1($command);
		}
	}

	if ($command->is_smb2) {
		my $error = 0;
		my $fid = $command->{fid};
		my $openfile = undef;

		if (($tid || exists $command->{fid}) && !$tree) {
			$error = SMB::STATUS_SMB_BAD_TID;
		}
		elsif ($fid) {
			$openfile = $connection->{openfiles}{@$fid}
				or $error = SMB::STATUS_FILE_CLOSED;
			$command->openfile($openfile);
		}

		if ($error) {
			# skip command processing
		}
		elsif ($command->is('SessionSetup')) {
			$command->header->{uid} = $connection->id;
		}
		elsif ($command->is('TreeConnect')) {
			my ($addr, $share) = $self->parse_share_uri($command->verify_uri);
			my $tree_root = $self->share_roots->{$share};
			if ($tree_root || $share eq 'IPC$') {
				my $tid = $command->header->{tid} = @{$connection->{trees}} + 1;
				push @{$connection->{trees}}, SMB::Tree->new($share, $tid, root => $tree_root);
			} else {
				$error = SMB::STATUS_BAD_NETWORK_NAME;
			}
		}
		elsif ($command->is('Create')) {
			my $file = SMB::File->new(name => $command->file_name, share_root => $tree->root);
			my $disposition = $command->disposition;
			if ($file->exists && $disposition == SMB::File::DISPOSITION_OPEN) {
				if ($command->requested_directory && !$file->is_directory) {
					$error = SMB::STATUS_NOT_A_DIRECTORY;
				} elsif ($command->requested_non_directory && $file->is_directory) {
					$error = SMB::STATUS_FILE_IS_A_DIRECTORY;
				}
			}
			unless ($error) {
				$openfile = $file->open_by_disposition($disposition);
				if ($openfile) {
					$fid = [ ++$connection->{last_fid}, 0 ];
					$connection->{openfiles}{@$fid} = $openfile;
					$command->fid($fid);
					$command->openfile($openfile);
				} else {
					$error = SMB::STATUS_NO_SUCH_FILE;
				}
			}
		}
		elsif ($command->is('Close')) {
			$openfile->close;
			delete $connection->{openfiles}{@$fid};
		}
		elsif ($command->is('Read')) {
			$command->{buffer} = $openfile->file->read(
				length => $command->{length},
				offset => $command->{offset},
				minlen => $command->{minimum_count},
				remain => $command->{remaining_bytes},
			);
			$error = SMB::STATUS_END_OF_FILE unless defined $command->{buffer};
		}
		elsif ($command->is('QueryDirectory')) {
			$command->{files} = $openfile->file->find_files(
				pattern => $command->file_pattern,
				start_idx => $command->file_index,
			);
			$error = SMB::STATUS_INVALID_PARAMETER unless defined $command->{files};
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
				my $connection = $self->add_connection($client_socket, ++$self->{client_id});
				unless ($connection) {
					$socket->close;
					next;
				}
				$self->on_connect($connection);
			}
			else {
				my $fd = $socket->fileno;
				my $connection = $connections->{$fd} || die "Unexpected data on unexisting fd $fd";
				my $command = $self->recv_command($connection);
				if (!$command) {
					$self->on_disconnect($connection);
					$self->delete_connection($connection);
					next;
				}
				$self->on_command($connection, $command);
			}
		}
	}
}

1;
