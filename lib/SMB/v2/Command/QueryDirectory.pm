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

package SMB::v2::Command::QueryDirectory;

use strict;
use warnings;

use parent 'SMB::v2::Command';

sub init ($) {
	$_[0]->set(
		info_level    => 0,
		flags         => 0,
		file_index    => 0,
		file_pattern  => '*',
		buffer_length => 65536,
		fid           => 0,
		openfile      => undef,
		files         => undef,
	)
}

sub parse ($$) {
	my $self = shift;
	my $parser = shift;

	if ($self->is_response) {
		my $offset = $parser->uint16;
		my $length = $parser->uint32;

		my @files = ();
		my $next_diff;
		do {
			my $current = $parser->offset;
			$next_diff = $parser->uint32;
			my $file_index = $parser->uint32;
			my @values = ((map { $parser->uint64 } 1 .. 6), $parser->uint32);
			my $length = $parser->uint32;
			my $ea_size = $parser->uint32;  # TODO
			my $short_length = $parser->uint8;
			$parser->uint8;
			my $short_filename = $parser->utf16($short_length);
			$parser->uint16;  # pad
			my $id = $parser->uint64;
			my $filename = $parser->utf16($length);
			my $file = SMB::File->new(index => $file_index, name => $filename, short_name => $short_filename, id => $id);
			$file->update(@values, 1);
			push @files, $file;
			$parser->bytes($current + $next_diff - $parser->offset) if $next_diff;
		} while $next_diff;

		$self->files(\@files);
	} else {
		$self->info_level($parser->uint8);
		$self->flags($parser->uint8);
		$self->file_index($parser->uint32);
		$self->fid($parser->fid2);
		my $offset = $parser->uint16;
		my $length = $parser->uint16;
		$self->buffer_length($parser->uint32);
		$self->file_pattern($parser->utf16($length));
	}

	return $self;
}

sub pack ($$) {
	my $self = shift;
	my $packer = shift;

	if ($self->is_response) {
		my $file_index = $self->file_index || 0;
		my $files = $self->files || [];

		return $self->abort_pack($packer, SMB::STATUS_NO_MORE_FILES)
			unless @$files;

		$packer
			->uint16(72)
			->stub('buffer-length', 'uint32')
			->mark('buffer-start')
		;

		my $length = 0;
		my $i = 0;
		for my $file (@$files) {
			my $filename = $file->name;
			my $short_filename = $file->{short_name} || '';

			$packer
				->mark('file-info-start')
				->stub('next-diff', 'uint32')
				->uint32($file_index + $i)
				->uint64($file->creation_time)
				->uint64($file->last_access_time)
				->uint64($file->last_write_time)
				->uint64($file->change_time)
				->uint64($file->end_of_file)
				->uint64($file->allocation_size)
				->uint32($file->attributes)
				->uint32(length($filename))
				->uint32($file->{ea_size} || 0)  # TODO
				->uint8 (length($short_filename))
				->uint8 (0)
				->utf16($short_filename)
				->uint16(0)  # TODO: pad
				->uint64($file->{id} || 0)
				->utf16($filename)
				->uint16(0)  # TODO: pad
				->fill('next-diff', ++$i == @$files ? 0 : $packer->diff('file-info-start'))
			;
		}

		$packer->fill('buffer-length', $packer->diff('buffer-start'));
	} else {
		$packer
			->uint8($self->info_level)
			->uint8($self->flags)
			->uint32($self->file_index)
			->fid2($self->fid || die "No fid set")
			->uint16($packer->diff('smb-header') + 8)
			->uint16(length($self->file_pattern))
			->uint32($self->buffer_length)
			->utf16($self->file_pattern)
		;
	}
}

1;
