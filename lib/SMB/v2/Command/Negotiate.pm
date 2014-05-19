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

use strict;
use warnings;

package SMB::v2::Command::Negotiate;

use parent 'SMB::v2::Command';

sub new_from_v1 ($$) {
	my $class = shift;
	my $command1 = shift;

	my $header1 = $command1->header;

	my $flags = $header1->{flags} & SMB::v1::Header::FLAGS_RESPONSE ? SMB::v2::Header::FLAGS_RESPONSE : 0;
	my $security_mode =
		($header1->{flags2} & SMB::v1::Header::FLAGS2_SECURITY_SIGNATURE ? 1 : 0) |
		($header1->{flags2} & SMB::v1::Header::FLAGS2_SECURITY_SIGNATURE_REQUIRED ? 2 : 0);

	my $header = SMB::v2::Header->new(
		code => 0,
		mid => 0,
		flags => $flags,
		status => $command1->status,
	);

	my $self = $class->SUPER::new($header);

	$self->set(security_mode => $security_mode);

	return $self;
}

sub init ($) {
	$_[0]->set(
		dialects          => [ 0x0202 ],
		dialect           => 0x0202,
		security_mode     => 0,
		capabilities      => 0x7,
		client_guid       => [ ("\0") x 16 ],
		max_transact_size => 1 << 20,
		max_read_size     => 1 << 16,
		max_write_size    => 1 << 16,
	)
}

sub parse ($$%) {
	my $self = shift;
	my $parser = shift;

	return $self;
}

sub pack ($$$) {
	my $self = shift;
	my $packer = shift;
	my $is_response = shift;

	if ($is_response) {
		$packer
			->uint16($self->security_mode)
			->uint16($self->dialect)
			->uint16(0)  # reserved
			->bytes ($self->client_guid)
			->uint32($self->capabilities)
			->uint32($self->max_transact_size)
			->uint32($self->max_read_size)
			->uint32($self->max_write_size)
			->uint64(0)  # current time
			->uint64(0)  # boot time
		;
	} else {
		my $dialects = $self->dialects;
		$packer
			->uint16(scalar @$dialects)
			->uint16($self->security_mode)
			->uint16(0)  # reserved
			->uint32($self->capabilities)
			->bytes ($self->client_guid)
			->uint64(0)  # boot time
		;
		$packer->uint16($_) for @$dialects;
	}
}

sub supports_protocol ($$) {
	my $self = shift;

	return 1;
}

1;
