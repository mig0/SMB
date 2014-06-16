# Games::Checkers, Copyright (C) 2014 Mikhael Goikhman, migo@cpan.org
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

use integer;

package SMB;

use SMB::Parser;
use SMB::Packer;
use SMB::v1::Commands;
use SMB::v2::Commands;

our $VERSION = 0.001;

use constant {
	STATUS_SUCCESS                  => 0x00000000,
	STATUS_PENDING                  => 0x00000103,
	STATUS_NOTIFY_ENUM_DIR          => 0x0000010c,
	STATUS_SMB_BAD_TID              => 0x00050002,
	STATUS_OS2_INVALID_LEVEL        => 0x007c0001,
	STATUS_NO_MORE_FILES            => 0x80000006,
	STATUS_INVALID_PARAMETER        => 0xc000000d,
	STATUS_NO_SUCH_DEVICE           => 0xc000000e,
	STATUS_NO_SUCH_FILE             => 0xc000000f,
	STATUS_END_OF_FILE              => 0xc0000011,
	STATUS_MORE_PROCESSING_REQUIRED => 0xc0000016,
	STATUS_NO_FREE_MEMORY           => 0xc0000017,
	STATUS_ACCESS_DENIED            => 0xc0000022,
	STATUS_BUFFER_TOO_SMALL         => 0xc0000023,
	STATUS_OBJECT_NAME_NOT_FOUND    => 0xc0000034,
	STATUS_OBJECT_NAME_COLLISION    => 0xc0000035,
	STATUS_OBJECT_PATH_NOT_FOUND    => 0xc000003a,
	STATUS_SHARING_VIOLATION        => 0xc0000043,
	STATUS_DELETE_PENDING           => 0xc0000056,
	STATUS_PRIVILEGE_NOT_HELD       => 0xc0000061,
	STATUS_DISK_FULL                => 0xc000007f,
	STATUS_FILE_IS_A_DIRECTORY      => 0xc00000ba,
	STATUS_BAD_NETWORK_NAME         => 0xc00000cc,
	STATUS_DIRECTORY_NOT_EMPTY      => 0xc0000101,
	STATUS_NOT_A_DIRECTORY          => 0xc0000103,
	STATUS_CANCELLED                => 0xc0000120,
	STATUS_CANNOT_DELETE            => 0xc0000121,
	STATUS_FILE_CLOSED              => 0xc0000128,
	STATUS_INVALID_LEVEL            => 0xc0000148,
	STATUS_FS_DRIVER_REQUIRED       => 0xc000019c,
	STATUS_NOT_A_REPARSE_POINT      => 0xc0000275,
};

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my $parser = delete $options{parser} // SMB::Parser->new;
	my $packer = delete $options{packer} // SMB::Packer->new;
	my $quiet  = delete $options{quiet};

	my $self = {
		parser => $parser,
		packer => $packer,
		disable_log => $quiet,
		%options,
	};

	bless $self, $class;
}

sub log ($$@) {
	my $self = shift;
	my $is_err = shift;
	my $format = shift;
	return if $self->disable_log;
	print sprintf("%s $format\n", $is_err ? '!' : '*', @_);
}

sub msg ($@) { shift()->log(0, @_) }
sub err ($@) { shift()->log(1, @_); return }

my $MAX_DUMP_BYTES = 8 * 1024;
my $dump_line_format = "%03x | 00 53 54 52 49 4E 47 aa  aa aa aa aa aa aa       | _STRING. ......   |\n";

sub mem ($$;$) {
	my $self = shift;
	my $data = shift;
	my $label = shift || "Data dump";
	return if $self->disable_log;

	my $len = length($data);
	$self->msg(sprintf("%s (%lu bytes%s):", $label, $len, $len > $MAX_DUMP_BYTES ? ", shorten" : ""), @_);
	$len = $MAX_DUMP_BYTES if $len > $MAX_DUMP_BYTES;

	for (my $n = 0; $n < ($len + 15) / 16; $n++) {
		for (my $i = 0; $i < 16; $i++) {
			my $valid = $n * 16 + $i < $len;
			my $b = $valid ? ord(substr($data, $n * 16 + $i, 1)) : undef;
			substr($dump_line_format, 7 + $i * 3 + ($i >= 8), 2) = $valid ? sprintf("%02x", $b) : "  ";
			substr($dump_line_format, 58 + $i + ($i >= 8), 1) = $valid ? $b == 0 ? '_' : $b <= 32 || $b >= 127 || $b == 37 ? '.' : chr($b) : ' ';
		}
		printf $dump_line_format, $n;
	}
}

sub parse_uint8  { $_[0]->parser->uint8;  }
sub parse_uint16 { $_[0]->parser->uint16; }
sub parse_uint32 { $_[0]->parser->uint32; }
sub parse_bytes  { $_[0]->parser->bytes($_[1]); }
sub parse_smb1   { SMB::v1::Commands->parse($_[0]->parser) }
sub parse_smb2   { SMB::v2::Commands->parse($_[0]->parser) }

sub pack_uint8  { $_[0]->packer->uint8($_[1]);  }
sub pack_uint16 { $_[0]->packer->uint16($_[1]); }
sub pack_uint32 { $_[0]->packer->uint32($_[1]); }
sub pack_bytes  { $_[0]->packer->bytes($_[1]); }
sub pack_smb1   { SMB::v1::Commands->pack(shift()->packer, shift, @_) }
sub pack_smb2   { SMB::v2::Commands->pack(shift()->packer, shift, @_) }

sub parse_share_uri ($$) {
	my $self = shift;
	my $share_uri = shift;

	unless ($share_uri) {
		$self->err("No share uri supplied");
		return;
	}
	unless ($share_uri =~ m~^([/\\])\1([\w.]+(?::\d+)?)\1([^/\\]+)(?:$|\1)~) {
		$self->err("Invalid share uri ($share_uri)");
		return;
	}

	return wantarray ? ($2, $3) : $share_uri;
}

our $AUTOLOAD;

sub AUTOLOAD ($;@) {
	my $self = shift;
	my @params = @_;

	my $method = $AUTOLOAD;
	$method =~ s/.*://g;

	return if $method eq 'DESTROY';  # ignore DESTROY messages

	die "Calling method $method for non-object '$self'\n"
		unless ref($self);

	if (exists $self->{$method}) {
		# define this accessor method explicitely if not yet
		no strict 'refs';
		*{$AUTOLOAD} = sub {
			my $self = shift;
			warn "Skipping extraneous params (@_) on access of field '$method' in $self\n"
				if @_ > 1;
			$self->{$method} = shift if @_;
			return $self->{$method};
		} unless $self->can($AUTOLOAD);

		return *{$AUTOLOAD}->($self, @params);
	}

	die "Unknown method or field '$method' in $self\n";
}

1;
