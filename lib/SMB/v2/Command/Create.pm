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

package SMB::v2::Command::Create;

use strict;
use warnings;

use parent 'SMB::v2::Command';

use SMB::File;

use constant {
	DISPOSITION_SUPERSEDE    => 0,  # exists ? supersede : create
	DISPOSITION_OPEN         => 1,  # exists ? open      : fail
	DISPOSITION_CREATE       => 2,  # exists ? fail      : create
	DISPOSITION_OPEN_IF      => 3,  # exists ? open      : create
	DISPOSITION_OVERWRITE    => 4,  # exists ? overwrite : fail
	DISPOSITION_OVERWRITE_IF => 5,  # exists ? overwrite : create

	OPTIONS_DIRECTORY_FILE            => 0x00000001,
	OPTIONS_WRITE_THROUGH             => 0x00000002,
	OPTIONS_SEQUENTIAL_ONLY           => 0x00000004,
	OPTIONS_NO_INTERMEDIATE_BUFFERING => 0x00000008,
	OPTIONS_SYNCHRONOUS_IO_ALERT      => 0x00000010,
	OPTIONS_SYNCRHONOUS_IO_NONALERT   => 0x00000020,
	OPTIONS_NON_DIRECTORY_FILE        => 0x00000040,
	OPTIONS_COMPLETE_IF_OPLOCKED      => 0x00000100,
	OPTIONS_NO_EA_KNOWLEDGE           => 0x00000200,
	OPTIONS_RANDOM_ACCESS             => 0x00000800,
	OPTIONS_DELETE_ON_CLOSE           => 0x00001000,
	OPTIONS_OPEN_BY_FILE_ID           => 0x00002000,
	OPTIONS_OPEN_FOR_BACKUP_INTENT    => 0x00004000,
	OPTIONS_NO_COMPRESSION            => 0x00008000,
	OPTIONS_RESERVE_OPFILTER          => 0x00100000,
	OPTIONS_OPEN_REPARSE_POINT        => 0x00200000,
	OPTIONS_OPEN_NO_RECALL            => 0x00400000,
	OPTIONS_OPEN_FOR_FREE_SPACE_QUERY => 0x00800000,

	ACTION_SUPERSEDED  => 0,  # existing file was deleted and new file was created in its place
	ACTION_OPENED      => 1,  # existing file was opened
	ACTION_CREATED     => 2,  # new file was created
	ACTION_OVERWRITTEN => 3,  # new file was overwritten
};

sub init ($) {
	$_[0]->set(
		security_flags  => 0,
		oplock          => 0,
		impersonation   => 0,
		create_flags    => 0,
		access_mask     => 0,
		file_attributes => 0,
		share_access    => 0,
		disposition     => 0,
		options         => 0,
		file_name       => '',

		flags           => 0,
		create_action   => 0,
		file            => undef,
		fid             => undef,
	)
}

sub parse ($$) {
	my $self = shift;
	my $parser = shift;

	if ($self->is_response) {
		my $file = SMB::File->new;

		$self->oplock($parser->uint8);
		$self->flags($parser->uint8);
		$self->create_action($parser->uint32);

		my @file_params = (
			$parser->uint64,  # creation_time
			$parser->uint64,  # last_access_time
			$parser->uint64,  # last_write_time
			$parser->uint64,  # change_time
			$parser->uint64,  # allocation_size
			$parser->uint64,  # end_of_file
			$parser->uint32,  # attributes
		);
		$file->update(@file_params);

		$parser->uint32;  # reserved
		$self->fid($parser->fid2);
		$self->file($file);
	} else {
		$self->security_flags($parser->uint8);
		$self->oplock($parser->uint8);
		$self->impersonation($parser->uint32);
		$self->create_flags($parser->uint64);
		$parser->uint64;  # reserved
		$self->access_mask($parser->uint32);
		$self->file_attributes($parser->uint32);
		$self->share_access($parser->uint32);
		$self->disposition($parser->uint32);
		$self->options($parser->uint32);
		my $name_offset = $parser->uint16;
		my $name_len = $parser->uint16;
		$parser->uint32(0);  # contexts
		$parser->uint32(0);
		$self->file_name($parser->utf16($name_len));
	}

	return $self;
}

sub pack ($$) {
	my $self = shift;
	my $packer = shift;

	if ($self->is_response) {
		my $file = $self->file;

		return $self->abort_pack($packer, SMB::STATUS_NO_SUCH_FILE)
			unless $file && $file->exists && $self->fid;

		$packer
			->uint8($self->oplock)
			->uint8($self->flags)
			->uint32($self->create_action)
			->uint64($file->creation_time)
			->uint64($file->last_access_time)
			->uint64($file->last_write_time)
			->uint64($file->change_time)
			->uint64($file->allocation_size)
			->uint64($file->end_of_file)
			->uint32($file->attributes)
			->uint32(0)  # reserved
			->fid2($self->fid)
			->uint32(0)  # contexts
			->uint32(0)
		;
	} else {
		$packer
			->uint8($self->security_flags)
			->uint8($self->oplock)
			->uint32($self->impersonation)
			->uint64($self->create_flags)
			->uint64(0)  # reserved
			->uint32($self->access_mask)
			->uint32($self->file_attributes)
			->uint32($self->share_access)
			->uint32($self->disposition)
			->uint32($self->options)
			->uint16($packer->diff('smb-header') + 10)
			->uint16(length($self->file_name) * 2)
			->uint32(0)  # contexts
			->uint32(0)
			->utf16($self->file_name)
		;
	}
}

sub requested_directory ($) {
	my $self = shift;

	return $self->options & OPTIONS_DIRECTORY_FILE ? 1 : 0;
}

sub requested_non_directory ($) {
	my $self = shift;

	return $self->options & OPTIONS_NON_DIRECTORY_FILE ? 1 : 0;
}

1;
