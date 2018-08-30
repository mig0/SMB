# SMB Perl library, Copyright (C) 2014-2018 Mikhael Goikhman, migo@cpan.org
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
use SMB::v2::Command::TreeConnect;
use SMB::v2::Command::Create;
use SMB::v2::Command::Close;
use SMB::v2::Command::QueryDirectory;
use SMB::v2::Command::Read;
use SMB::v2::Command::Write;
use SMB::v2::Command::SetInfo;
use SMB::Tree;

sub new ($$%) {
	my $class = shift;
	my $share_uri = shift;
	my %options = @_;

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
		$self->set_credentials(%options);

		my ($conn_key) = $self->add_connection(
			$socket, --$self->{server_id},
			addr     => $addr,
			share    => $share,
			use_anon => $self->use_anon,
			username => $self->username,
			password => $self->password,
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

sub set_credentials ($%) {
	my $self = shift;
	my %options = @_;

	$options{$_} //= $self->{$_} for qw(use_anon username password);

	if ($options{use_anon}) {
		$self->{use_anon} = 1;
		$self->{username} = '';
		$self->{password} = '';
	} else {
		$self->{use_anon} = 0;
		$self->{username} = $options{username};
		$self->{password} = $options{password};
	}

	die "No username for client credentials\n" unless defined $self->username;
	die "No password for client credentials\n" unless defined $self->password;
}

sub get_curr_connection ($) {
	my $self = shift;

	my $connections = $self->connections;
	unless (%$connections) {
		$self->err("Called get_curr_connection without established connections");
		return;
	}

	my $connection = $connections->{$self->curr_conn_key};
	unless ($connection) {
		$self->err("Called get_curr_connection when curr_conn_key is invalid");
		return;
	}

	return $connection;
}

sub find_connection_by_tree ($$) {
	my $self = shift;
	my $tree = shift // die;

	for (values %{$self->connections}) {
		return $_ if $_->tree == $tree;
	}

	$self->err("Can't find connection for $tree");
	return;
}

sub process_request ($$$%) {
	my $self = shift;
	my $connection = shift;
	my $command_name = shift;
	my %command_options = @_;

	my $command_class = "SMB::v2::Command::$command_name";
	my $command_code = $SMB::v2::Commands::command_codes{$command_name};
	my $no_warn = delete $command_options{_no_warn};

	my $request = $command_class->new(
		SMB::v2::Header->new(
			mid  => $connection->{message_id}++,
			uid  => $connection->session_id,
			tid  => $connection->tree ? $connection->tree->id : 0,
			code => $command_code,
		),
	);
	$request->set(%command_options);

	$connection->send_command($request);
	$connection->sent_request($request);

	my $response = $self->wait_for_response($connection);

	warn "SMB Error on $command_name response: " . ($response ? $response->status_name : "internal") . "\n"
		if !$no_warn && (!$response || $response->is_error);

	return $response;
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
		_no_warn => 1,
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
			use_anon => $connection->use_anon,
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

sub check_session ($;$) {
	my $self = shift;
	my $connection = shift || $self->get_curr_connection;

	return
		$self->process_negotiate_if_needed($connection) &&
		$self->process_sessionsetup_if_needed($connection);
}

sub connect_tree ($%) {
	my $self = shift;
	my %options = @_;

	my $connection = $self->get_curr_connection || return;

	my ($addr, $share) =
		map { $options{$_} || $connection->{$_} || die "No $_ to connect_tree\n" }
		qw(addr share);

	$self->set_credentials(%options);

	return unless $self->check_session($connection);

	$addr =~ s/:\d+//;
	my $response = $self->process_request($connection, 'TreeConnect', uri => "\\\\$addr\\$share");
	if ($response && $response->is_success) {
		my $tree = SMB::Tree->new(
			$share, $response->header->tid,
			addr   => $addr,
			client => $self,
			cwd    => '',
		);
		$connection->tree($tree);
		return $tree;
	}

	return;
}

sub _normalize_path ($$;$) {
	my $path = shift // '';
	my $base = shift // '';
	my $to_dos = shift || 0;

	$path = "$base/$path" if $path =~ m!^[^/]!;

	$path =~ s![/\\]+$!/!g;  # to unix
	# remove "./", "any/../", "../.." at the end
	while ($path =~ s=(^|/)\.(?:/|$)=$1=g) {}
	while ($path =~ s=(^|/)(?!\.\./)[^/]+/\.\.(?:/|$)=$1=g) {}
	$path =~ s!(?:(?:^|/)\.\.)+/?$!!;
	$path =~ s!/$!!;

	if ($to_dos) {
		$path =~ s=^/==;
		$path =~ s=/=\\=g;
	}

	return $path;
}

sub _basename ($;$) {
	my $path = shift // '';
	my $is_dos = shift || 0;

	my $delim = $is_dos ? '\\' : '/';

	return $path =~ /.*\Q$delim\E(.*)/ ? $1 : $path;
}

sub dnload_file ($$$$) {
	my $self = shift;
	my $connection = shift;
	my $filename = shift // return $self->err("No remote file name to download");
	my $dst_filename = shift // return $self->err("No local file name to save");

	my $response = $self->process_request($connection, 'Create',
		file_name => $filename,
	);
	return unless $response && $response->is_success;

	my $file = $response->openfile->file;
	my $fid = $response->fid;
	my $remaining = $file->end_of_file;
	my $time = $file->mtime;
	my $content = '';
	my $offset = 0;
	while ($remaining) {
		my $length = $remaining >= 65536 ? 65536 : $remaining;
		$remaining -= $length;
		$response = $self->process_request($connection, 'Read',
			fid => $fid,
			offset => $offset,
			length => $length,
			remaining_bytes => $remaining,
		);
		return unless $response && $response->is_success;
		my $read = $response->length;
		return $self->err("Unexpected $read bytes read instead of $length at offset $offset")
			if $read != $length;
		$content .= $response->buffer;
		$offset += $length;
	}
	$self->process_request($connection, 'Close',
		fid => $fid,
	);

	open DST, '>', $dst_filename
		or return $self->err("Can't open $dst_filename for write: $!");
	print DST $content
		or return $self->err("Can't write content to $dst_filename: $!");
	close DST
		or return $self->err("Can't close $dst_filename after write: $!");

	# consider to set $time on file
	return 1;
}

sub upload_file ($$$$) {
	my $self = shift;
	my $connection = shift;
	my $filename = shift // return $self->err("No local file name to load");
	my $dst_filename = shift // return $self->err("No remote file name to upload");

	local $/ = undef;
	open SRC, '<', $filename
		or return $self->err("Can't open $filename for read: $!");
	my $content = <SRC>
		// return $self->err("Can't read content from $filename: $!");
	close SRC
		or return $self->err("Can't close $filename after read: $!");

	my $response = $self->process_request($connection, 'Create',
		file_name => $dst_filename,
		options => SMB::v2::Command::Create::OPTIONS_NON_DIRECTORY_FILE,
		access_mask => 0x12019f,
		disposition => SMB::File::DISPOSITION_OVERWRITE_IF,
	);
	return unless $response && $response->is_success;
	my $fid = $response->fid;
	my $remaining = length($content);
	my $offset = 0;
	while ($remaining) {
		my $length = $remaining >= 65536 ? 65536 : $remaining;
		$remaining -= $length;
		$response = $self->process_request($connection, 'Write',
			fid => $fid,
			offset => $offset,
			remaining_bytes => $remaining,
			buffer => substr($content, $offset, $length),
		);
		return unless $response && $response->is_success;
		my $written = $response->length;
		return $self->err("Unexpected $written bytes written instead of $length at offset $offset")
			if $written != $length;
		$offset += $length;
	}
	$self->process_request($connection, 'Close',
		fid => $fid,
	);

	return 1;
}

sub remove_file ($$$$) {
	my $self = shift;
	my $connection = shift;
	my $file = shift // return $self->err("No file to remove");
	my $recursive = shift;

	my $remove_using_setinfo = $ENV{SMB_CLIENT_REMOVE_FILE_USING_SETINFO};

	my $options = $file->is_directory
		? SMB::v2::Command::Create::OPTIONS_DIRECTORY_FILE
		: SMB::v2::Command::Create::OPTIONS_NON_DIRECTORY_FILE;
	$options |= SMB::v2::Command::Create::OPTIONS_DELETE_ON_CLOSE
		unless $remove_using_setinfo;
	my $response = $self->process_request($connection, 'Create',
		file_name => $file->name,
		options => $options,
		access_mask => 0x10081,
	);
	return unless $response && $response->is_success;
	my $fid = $response->fid;

	if ($remove_using_setinfo) {
		$response = $self->process_request($connection, 'SetInfo',
			fid => $fid,
			type => SMB::v2::Command::SetInfo::TYPE_FILE,
			level => SMB::v2::Command::SetInfo::FILE_LEVEL_DISPOSITION,
			buffer => chr(SMB::v2::Command::SetInfo::FILE_DISPOSITION_DELETE_ON_CLOSE),
		);
		return unless $response && $response->is_success;
	}

	if ($recursive && $file->is_directory) {
		my @files = ();
		while (1) {
			$response = $self->process_request($connection, 'QueryDirectory',
				file_pattern => "*",
				fid => $fid,
			);
			last if $response && $response->status == SMB::STATUS_NO_MORE_FILES;
			return $self->err("Failed to get file list in " . $file->name)
				unless $response && $response->is_success;
			push @files, @{$response->files};
		}
		my $dirname = $file->name;
		for my $file (@files) {
			# TODO: consider to have full file name already on parse-response
			$file->name("$dirname\\" . $file->name) if $dirname;
			next if $file->name =~ m/(^|\\)\.\.?$/;
			return $self->err("Failed to remove inner ". $file->name)
				unless $self->remove_file($connection, $file, 1);
		}
	}

	$self->process_request($connection, 'Close',
		fid => $fid,
	);
	return unless $response && $response->is_success;

	return 1;
}

sub rename_file ($$$$;$) {
	my $self = shift;
	my $connection = shift;
	my $filename1 = shift // return $self->err("No old filename to rename");
	my $filename2 = shift // return $self->err("No new filename to rename");
	my $force = shift || 0;

	my $response = $self->process_request($connection, 'Create',
		file_name => $filename1,
		options => 0,
		access_mask => 0x10081,
	);
	return unless $response && $response->is_success;
	my $fid = $response->fid;

	my $rename_struct = SMB::Packer->new
		->uint8($force ? 1 : 0)
		->zero(7)    # reserved
		->zero(8)    # root dir handle
		->uint16(length($filename2) * 2)
		->uint16(0)  # reserved
		->str($filename2);

	$response = $self->process_request($connection, 'SetInfo',
		fid => $fid,
		type => SMB::v2::Command::SetInfo::TYPE_FILE,
		level => SMB::v2::Command::SetInfo::FILE_LEVEL_RENAME,
		buffer => $rename_struct->data,
	);
	return unless $response && $response->is_success;

	$self->process_request($connection, 'Close',
		fid => $fid,
	);
	return unless $response && $response->is_success;

	return 1;
}

sub perform_tree_command ($$$@) {
	my $self = shift;
	my $tree = shift;
	my $command = shift;

	my $connection = $self->find_connection_by_tree($tree) || return;
	my %options = @_ && ref($_[0]) eq 'HASH' ? %{shift()} : ();

	if ($command eq 'chdir') {
		my $dir = shift // '';

		$tree->cwd(_normalize_path($dir, $tree->cwd));
	}
	elsif ($command eq 'find') {
		my $pattern = _normalize_path(shift || "*", $tree->cwd, 1);
		my $dirname = $pattern =~ /^(.*)\\(.*)/ ? $1 : "";
		$pattern = $2 if $2;

		my $response = $self->process_request($connection, 'Create',
			file_name => $dirname,
			file_attributes => SMB::File::ATTR_DIRECTORY,
		);
		return unless $response && $response->is_success;
		my $fid = $response->fid;

		my $files = [];
		my $success = 1;
		while (1) {
			$response = $self->process_request($connection, 'QueryDirectory',
				file_pattern => $pattern,
				fid => $fid,
			);
			if ($response) {
				last if $response->status == SMB::STATUS_NO_MORE_FILES;
				unless ($response->is_success) {
					$success = 0;
					last;
				}
			}
			else {
				$success = 0;
				last;
			}
			push @$files, @{$response->files};
		}

		$self->process_request($connection, 'Close',
			fid => $fid,
		);

		return unless $success;
		return wantarray ? @$files : $files;
	}
	elsif ($command eq 'dnload') {
		my $filename = shift // '';
		return $self->err("No filename") if $filename eq '';
		$filename = _normalize_path($filename, $tree->cwd, 1);
		my $dst_filename = _normalize_path(shift || _basename($filename, 1), '.');

		return $self->dnload_file($connection, $filename, $dst_filename);
	}
	elsif ($command eq 'upload') {
		my $filename = shift // '';
		return $self->err("No filename") if $filename eq '';
		$filename = _normalize_path($filename, '.');
		my $dst_filename = _normalize_path(shift || _basename($filename), $tree->cwd, 1);

		return $self->upload_file($connection, $filename, $dst_filename);
	}
	elsif ($command eq 'remove') {
		my $filename = shift // '';
		return $self->err("No filename") if $filename eq '';
		$filename = _normalize_path($filename, $tree->cwd, 1);

		my $recursive = $options{recursive};
		my $is_dir = shift // $recursive;
		my $file = SMB::File->new(name => $filename, is_directory => $is_dir);

		return $self->remove_file($connection, $file, $recursive);
	}
	elsif ($command eq 'rename') {
		my $filename1 = shift // '';
		return $self->err("No filename1") if $filename1 eq '';
		$filename1 = _normalize_path($filename1, $tree->cwd, 1);
		my $filename2 = shift // '';
		return $self->err("No filename2") if $filename2 eq '';
		$filename2 = _normalize_path($filename2, $tree->cwd, 1);
		my $force = $options{force};

		return $self->rename_file($connection, $filename1, $filename2, $force);
	}
	elsif ($command eq 'copy') {
		my $filename1 = shift // '';
		return $self->err("No filename1") if $filename1 eq '';
		$filename1 = _normalize_path($filename1, $tree->cwd, 1);
		my $filename2 = shift // '';
		return $self->err("No filename2") if $filename2 eq '';
		$filename2 = _normalize_path($filename2, $tree->cwd, 1);

		my $tmp_filename = "/var/tmp/copy-$$";
		my $success =
			$self->dnload_file($connection, $filename1, $tmp_filename) &&
			$self->upload_file($connection, $tmp_filename, $filename2);
		unlink $tmp_filename;

		return $success;
	}

	return;
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

	my ($response) = $connection->recv_command;
	if (!$response) {
		$self->delete_connection($connection);
		return;
	}

	if ($response->is_response_to($request) && $response->status == SMB::STATUS_PENDING) {
		$self->dbg("Ignoring STATUS_PENDING response");
		($response) = $connection->recv_command;
	}

	unless ($response->is_response_to($request)) {
		$self->err("Unexpected: " . $response->to_string);
		return;
	}

	return $response;
}

1;
