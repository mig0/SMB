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

package SMB::v2::Command::SessionSetup;

use strict;
use warnings;

use parent 'SMB::v2::Command';

sub init ($) {
	$_[0]->set(
		flags => 0,
		security_mode => 0,
		capabilities => 0,
		previous_session_id => 0,
		security_buffer => '',
	)
}

sub parse ($$%) {
	my $self = shift;
	my $parser = shift;

	return $self;
}

sub prepare_response ($) {
	my $self = shift;

	$self->SUPER::prepare_response;

	my $more_processing = $self->header->{mid} == 2;

	$self->{security_buffer} = $more_processing
		? "\xa1\x81\xc4\x30\x81\xc1\xa0\x03\x0a\x01\x01\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x81\xab\x04\x81\xa8\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x10\x00\x10\x00\x38\x00\x00\x00\x15\x82\x8a\x62\x65\xc7\x2c\xd4\xd1\xa9\x1b\x24\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00\x60\x00\x48\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f\x57\x00\x49\x00\x4e\x00\x2d\x00\x37\x00\x2d\x00\x33\x00\x32\x00\x02\x00\x10\x00\x57\x00\x49\x00\x4e\x00\x2d\x00\x37\x00\x2d\x00\x33\x00\x32\x00\x01\x00\x10\x00\x57\x00\x49\x00\x4e\x00\x2d\x00\x37\x00\x2d\x00\x33\x00\x32\x00\x04\x00\x10\x00\x77\x00\x69\x00\x6e\x00\x2d\x00\x37\x00\x2d\x00\x33\x00\x32\x00\x03\x00\x10\x00\x77\x00\x69\x00\x6e\x00\x2d\x00\x37\x00\x2d\x00\x33\x00\x32\x00\x07\x00\x08\x00\x20\x67\xf3\xb5\x0a\x76\xcf\x01\x00\x00\x00\x00"
		: "\xa1\x07\x30\x05\xa0\x03\x0a\x01\x00";

	$self->set_status(SMB::STATUS_MORE_PROCESSING_REQUIRED) if $more_processing;

	$self->header->{uid} ||= rand(1000000);
}

sub pack ($$) {
	my $self = shift;
	my $packer = shift;

	if ($self->is_response) {
		$packer
			->uint16(0)  # session flags
			->uint16($packer->diff('smb-header') + 4)
			->uint16(length($self->security_buffer))
			->bytes ($self->security_buffer)
		;
	} else {
		$packer
			->uint8 ($self->flags)
			->uint8 ($self->security_mode)
			->uint32($self->capabilities)
			->uint32(0)  # channel
			->uint16($packer->diff('smb-header') + 12)
			->uint16(length $self->security_buffer)
			->uint64($self->previous_session_id)
			->bytes ($self->security_buffer)
		;
	}
}

1;
