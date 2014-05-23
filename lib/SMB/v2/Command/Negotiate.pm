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

package SMB::v2::Command::Negotiate;

use strict;
use warnings;

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

	$self->set(
		security_mode => $security_mode,
		dialects => [ 0x0202, 0x02ff ],
	);

	return $self;
}

sub init ($) {
	$_[0]->set(
		dialects          => [ 0x0202 ],
		dialect           => 0x0202,
		security_mode     => 0,
		capabilities      => 0x7,
		client_guid       => [ ("\5") x 16 ],
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

sub pack ($$) {
	my $self = shift;
	my $packer = shift;

	if ($self->is_response) {
		my $security_buffer =
			"\x60\x28\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x1e\x30\x1c\xa0\x1a\x30\x18\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";

		$packer
			->uint16($self->security_mode)
			->uint16($self->dialects->[1] || $self->dialect)
			->uint16(0)  # reserved
			->bytes ($self->client_guid)
			->uint32($self->capabilities)
			->uint32($self->max_transact_size)
			->uint32($self->max_read_size)
			->uint32($self->max_write_size)
			->uint64(0)  # current time
			->uint64(0)  # boot time
			->uint16($packer->get_stored_diff('smb-header') + 8)
			->uint16(length($security_buffer))
			->uint32(0)  # reserved2
			->bytes ($security_buffer)
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
