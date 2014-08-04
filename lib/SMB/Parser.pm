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

package SMB::Parser;

use strict;
use warnings;

use bytes;
use if (1 << 32 == 1), 'bigint';  # support native uint64 on 32-bit platforms
use Encode 'decode';

sub new ($$) {
	my $class = shift;
	my $data = shift // "";

	my $self = bless {}, $class;

	return $self->set($data);
}

sub reset ($;$) {
	my $self = shift;
	my $offset = shift || 0;

	$self->{offset} = $offset;

	return $self;
}

sub set ($$;$) {
	my $self = shift;

	$self->{data} = $_[0];
	$self->{size} = length($_[0]);

	return $self->reset($_[1]);
}

sub data { $_[0]->{data} }
sub size { $_[0]->{size} }
sub offset { $_[0]->{offset} }

my %UINT_MODS = (
	+1 => 'C',
	+2 => 'v',
	+4 => 'V',
	-1 => 'C',
	-2 => 'n',
	-4 => 'N',
);

sub uint ($$;$) {
	my $self = shift;
	my $n_bytes = shift;
	my $be_factor = shift() ? -1 : 1;

	return unpack($UINT_MODS{$be_factor * $n_bytes}, $self->bytes($n_bytes));
}

sub str ($$;$) {
	my $self = shift;
	my $n_bytes = shift;
	my $enc = shift || 'UTF-16LE';

	return decode($enc, $self->bytes($n_bytes));
}

sub bytes ($$) {
	my $self = shift;
	my $n_bytes = shift;

	my $n_avail = $self->{offset} + $n_bytes > $self->{size}
		? $self->{size} - $self->{offset} : $n_bytes;

	my $bytes = $self->{offset} > $self->{size} ? '' : substr($self->{data}, $self->{offset}, $n_avail);
	$self->{offset} += $n_bytes;

	return wantarray ? split('', $bytes) : $bytes;
}

sub skip ($) {
	my $self = shift;
	my $n_bytes = shift;

	$self->{offset} += $n_bytes;

	return $self;
}

sub uint8     { uint($_[0], 1   ); }
sub uint16    { uint($_[0], 2   ); }
sub uint32    { uint($_[0], 4   ); }
sub uint16_be { uint($_[0], 2, 1); }
sub uint32_be { uint($_[0], 4, 1); }
sub uint64    { uint32($_[0]) + (uint32($_[0]) << 32); }
sub utf16     { str($_[0], $_[1]); }
sub utf16_be  { str($_[0], $_[1], 'UTF-16BE'); }
sub fid1      { uint16($_[0]); }
sub fid2      { [ uint64($_[0]), uint64($_[0]) ]; }

1;
