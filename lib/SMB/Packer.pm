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

sub new ($$) {
	my $class = shift;

	my $self = bless {}, $class;

	return $self->reset;
}

sub reset ($) {
	my $self = shift;

	$self->{data} = '';
	$self->{offset} = 0;
	$self->{stored} = {};

	return $self;
}

sub size ($) {
	my $self = shift;

	return length($self->{data});
}

sub null ($$) {
	my $self = shift;
	my $n_bytes = shift // die;

	substr($self->{data}, $self->{offset}, $n_bytes) = '\0' x $n_bytes;

	return $self->skip($n_bytes);
}

sub skip ($$) {
	my $self = shift;
	my $n_bytes = shift // die;

	my $n_avail = $self->{offset} + $n_bytes > $self->size
		? $self->size - $self->{offset} : $n_bytes;

	$self->null($n_bytes - $n_avail) if $n_avail < $n_bytes;

	$self->{offset} += $n_avail;

	return $self;
}

sub store ($$) {
	my $self = shift;
	my $name = shift // '';

	$self->{stored}{$name} = $self->{offset};

	return $self;
}

sub restore ($$) {
	my $self = shift;
	my $name = shift // '';

	$self->{offset} = $self->{stored}{$name} || 0;

	return $self;
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

sub bytes ($$) {
	my $self = shift;
	my $data = shift;

	substr($self->{data}, $self->{offset}, length($data)) = $data;
	$self->{offset} += length($data);

	return $self;
}

sub uint8     { uint($_[0], 1, 0, $_[1]); }
sub uint16    { uint($_[0], 2, 0, $_[1]); }
sub uint32    { uint($_[0], 4, 0, $_[1]); }
sub uint16_be { uint($_[0], 2, 1, $_[1]); }
sub uint32_be { uint($_[0], 4, 1, $_[1]); }

1;
