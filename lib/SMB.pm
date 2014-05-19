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

sub export_constants (;$) {
	my $level = shift || 0;
}

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
sub err ($@) { shift()->log(1, @_) }

my $MAX_DUMP_BYTES = 8 * 1024;
my $dump_line_format = "%03x | 00 53 54 52 49 4E 47 aa  aa aa aa aa aa aa       | _STRING. ......   |\n";

sub mem ($$;$) {
	my $self = shift;
	my $data = shift;
	my $label = shift || "Data dump";
	return if $self->disable_log;

	my $len = length($data);
	$self->msg(sprintf "%s (%lu bytes%s):", $label, $len, $len > $MAX_DUMP_BYTES ? ", shorten" : "");
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

sub parser_set ($$) {
	my $self = shift;

	$self->parser->set($_[0]);
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
		warn "Redundant params (@params) on implicit access of field '$method' in $self\n"
			if @params;
		# define this accessor method explicitely if not yet
		no strict 'refs';
		*{$AUTOLOAD} = sub {
			shift()->{$method}
		} unless $self->can($AUTOLOAD);
		return $self->{$method};
	}

	die "Unknown method or field '$method' in $self\n";
}

1;
