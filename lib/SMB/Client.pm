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

use SMB::v2::Commands;
use SMB::v2::Command::Negotiate;
use SMB::v2::Command::SessionSetup;
use SMB::Tree;

sub new ($$%) {
	my $class = shift;
	my $share_uri = shift;
	my %options = @_;

	my $quiet   = delete $options{quiet}   || 0;
	my $verbose = delete $options{verbose} || 0;

	my $self = $class->SUPER::new(
		%options,
		server_id => 0,  # running index
		curr_conn_key => undef,  # key in connections hash
		unique_conn_addr => 1,
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
		my ($conn_key) = $self->add_connection(
			$socket, --$self->{server_id},
			addr     => $addr,
			share    => $share,
			username => $options{username},
			password => $options{password},
			tree     => undef,
			cwd      => '',
			openfiles => {},
			dialect      => undef,
			session_id   => 0,
			message_id   => 0,
			sent_request => undef,
		);

		$self->curr_conn_key($conn_key);
	}

	return $self;
}

sub get_curr_connection ($) {
	my $self = shift;

	my $connections = $self->connections;
	unless (%$connections) {
		$self->err("Called get_connection when no connections established");
		return;
	}

	my $connection = $connections->{$self->curr_conn_key};
	unless ($connection) {
		$self->err("Called get_connection when curr_conn_key is invalid");
		return;
	}

	return $connection;
}

sub process_request ($$$%) {
	my $self = shift;
	my $connection = shift;
	my $command_name = shift;
	my %command_options = @_;

	my $command_class = "SMB::v2::Command::$command_name";
	my $command_code = $SMB::v2::Commands::command_codes{$command_name};

	my $request = $command_class->new(
		SMB::v2::Header->new(
			mid  => $connection->{message_id}++,
			uid  => $connection->session_id,
			code => $command_code,
		),
	);
	$request->set(%command_options);

	$connection->send_command($request);
	$connection->sent_request($request);

	return $self->wait_for_response($connection);;
}

sub process_negotiate_if_needed ($$) {
	my $self = shift;
	my $connection = shift;

	return 1 if $connection->dialect;

	my $response = $self->process_request($connection, 'Negotiate');
	if ($response && $response->is_success) {
		unless ($connection->auth->process_spnego($response->security_buffer)) {
			$self->err("Server does not support our negotiation mechanism, expect problems on SessionSetup");
		}
		$connection->dialect($response->dialect);
		return 1;
	}

	return 0;
}

sub process_sessionsetup_if_needed ($$) {
	my $self = shift;
	my $connection = shift;

	return 1 if $connection->session_id;

	my $response = $self->process_request($connection, 'SessionSetup',
		security_buffer => $connection->auth->generate_spnego,
	);
	my $more_processing = $response->status == SMB::STATUS_MORE_PROCESSING_REQUIRED;
	return 0
		unless $response && ($response->is_success || $more_processing)
		&& $connection->auth->process_spnego($response->security_buffer);
	$connection->session_id($response->header->uid);
	return 1 if $response->is_success;
	return 0 unless $more_processing;

	$response = $self->process_request($connection, 'SessionSetup',
		security_buffer => $connection->auth->generate_spnego(
			username => $connection->username,
			password => $connection->password,
		),
	);
	if ($response && $response->is_success && $connection->auth->process_spnego($response->security_buffer)) {
		die "Got different session id on second SessionSetup"
			unless $connection->session_id == $response->header->uid;
		return 1;
	}

	return 0;
}

sub check_session ($$) {
	my $self = shift;
	my $connection = shift;

	return
		$self->process_negotiate_if_needed($connection) &&
		$self->process_sessionsetup_if_needed($connection);
}

sub connect_tree ($%) {
	my $self = shift;
	my %options = @_;

	my $connection = $self->get_curr_connection || return;

	my ($addr, $share, $username, $password) =
		map { $connection->{$_} || $options{$_} || die "No $_ to connect_tree\n" }
		qw(addr share username password);

	return unless $self->check_session($connection);

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

	$self->cwd($self->normalize_path($dir));
}

sub on_response ($$$$) {
	my $self = shift;
	my $connection = shift;
	my $response = shift;
	my $request = shift;

	return 0;
}

sub wait_for_response ($$) {
	my $self = shift;
	my $connection = shift;
	my $request = $connection->sent_request;

	return unless $request;

	my $response = $connection->recv_command;
	if (!$response) {
		$self->delete_connection($connection);
		return;
	}

	unless ($response->is_response_to($request)) {
		$self->err("Unexpected: " . $response->dump);
		return;
	}

	return $response;
}

1;
