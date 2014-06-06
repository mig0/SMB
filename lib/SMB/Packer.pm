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

package SMB::Packer;

use strict;
use warnings;

use bytes;
use Encode 'encode';

sub new ($$) {
	my $class = shift;

	my $self = bless {}, $class;

	return $self->reset;
}

sub reset ($) {
	my $self = shift;

	$self->{data} = '';
	$self->{offset} = 0;
	$self->{marks} = {};
	$self->{stubs} = {};

	return $self;
}

sub data { $_[0]->{data} }
sub size { length($_[0]->{data}) }

sub zero ($$) {
	my $self = shift;
	my $n_bytes = shift // die;

	substr($self->{data}, $self->{offset}, $n_bytes) = "\0" x $n_bytes;

	return $self->skip($n_bytes);
}

sub skip ($$) {
	my $self = shift;
	my $n_bytes = shift // die;

	my $n_avail = $self->{offset} + $n_bytes > $self->size
		? $self->size - $self->{offset} : $n_bytes;

	$self->zero($n_bytes - $n_avail) if $n_avail < $n_bytes;

	$self->{offset} += $n_avail;

	return $self;
}

sub stub ($$$) {
	my $self = shift;
	my $name = shift // '';
	my $type = shift // '';

	die "type must be either bytes with size or uint{8,16,32,64}"
		unless $type =~ /^uint(8|16|32|64)$/ || $type =~ /^\d+$/;
	$self->{stubs}{$name} = [ $self->{offset}, $type ];

	$type =~ /^\d+$/
		? $self->bytes("\0" x $type)
		: $self->$type(0);

	return $self;
}

sub fill ($$) {
	my $self = shift;
	my $name = shift // '';
	my $data = shift // die;

	my $curr_offset = $self->{offset};
	my ($offset, $type) = @{$self->{stubs}{$name}};
	$self->{offset} = $offset;
	$type =~ /^\d+$/
		? $self->bytes($data)
		: $self->$type($data);
	$self->{offset} = $curr_offset;

	return $self;
}

sub mark ($$) {
	my $self = shift;
	my $name = shift // '';

	$self->{marks}{$name} = $self->{offset};

	return $self;
}

sub jump ($$) {
	my $self = shift;
	my $name = shift // '';

	$self->{offset} = $self->{marks}{$name} || 0;

	return $self;
}

sub diff ($$) {
	my $self = shift;
	my $name = shift // '';

	return $self->{offset} - ($self->{marks}{$name} || 0);
}

my %UINT_MODS = (
	+1 => 'C',
	+2 => 'v',
	+4 => 'V',
	-1 => 'C',
	-2 => 'n',
	-4 => 'N',
);

sub uint ($$$$) {
	my $self = shift;
	my $n_bytes = shift;
	my $be_factor = shift() ? -1 : 1;
	my $i = shift;

	return $self->bytes(pack($UINT_MODS{$be_factor * $n_bytes}, $i));
}

sub str ($$;$) {
	my $self = shift;
	my $str = shift;
	my $enc = shift || 'UTF-16LE';

	return $self->bytes(encode($enc, $str));
}

sub bytes ($$) {
	my $self = shift;
	my $data = shift;

	$data = join('', @$data) if ref($data) eq 'ARRAY';

	substr($self->{data}, $self->{offset}, length($data)) = $data;
	$self->{offset} += length($data);

	return $self;
}

sub uint8     { uint($_[0], 1, 0, $_[1]); }
sub uint16    { uint($_[0], 2, 0, $_[1]); }
sub uint32    { uint($_[0], 4, 0, $_[1]); }
sub uint16_be { uint($_[0], 2, 1, $_[1]); }
sub uint32_be { uint($_[0], 4, 1, $_[1]); }
sub uint64    { uint32($_[0], $_[1] & 0xffffffff); uint32($_[0], $_[1] >> 32); }
sub utf16     { str($_[0], $_[1]); }
sub utf16_be  { str($_[0], $_[1], 'UTF-16BE'); }
sub fid1      { uint16($_[0], $_[1]); }
sub fid2      { uint64($_[0], $_[1][0]); uint64($_[0], $_[1][1]); }

1;
