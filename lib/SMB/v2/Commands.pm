# SMB-Perl library, Copyright (C) 2014 Mikhael Goikhman, migo@cpan.org
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

package SMB::v2::Commands;

use SMB::v2::Header;

our $header_stamp = "\xfeSMB";

our @command_names = (
	'Negotiate',       # 0x00
	'SessionSetup',    # 0x01
	'SessionLogoff',   # 0x02
	'TreeConnect',     # 0x03
	'TreeDisconnect',  # 0x04
	'Create',          # 0x05
	'Close',           # 0x06
	'Flush',           # 0x07
	'Read',            # 0x08
	'Write',           # 0x09
	'Lock',            # 0x0A
	'Ioctl',           # 0x0B
	'Cancel',          # 0x0C
	'KeepAlive',       # 0x0D
	'QueryDirectory',  # 0x0E
	'ChangeNotify',    # 0x0F
	'QueryInfo',       # 0x10
	'SetInfo',         # 0x11
	'Break',           # 0x12
);

our %command_aliases = (
	'Echo'    => 'KeepAlive',
	'Find'    => 'QueryDirectory',
	'Notify'  => 'ChangeNotify',
	'GetInfo' => 'QueryInfo',
);

our $MIN_MESSAGE_SIZE = 64;

sub parse ($$) {
	my $class = shift;
	my $parser = shift || die;

	if ($parser->size < $MIN_MESSAGE_SIZE) {
		warn sprintf "Too short message to parse (%d, should be at least %d)\n", $parser->size, $MIN_MESSAGE_SIZE;
		return;
	}

	# parse header following the SMB2 stamp "\xfeSMB"
	$parser->uint16;  # skip reserved
	my $credit_charge = $parser->uint16;
	my $status = $parser->uint32;
	my $code   = $parser->uint16;
	my $credits = $parser->uint16;
	my $flags  = $parser->uint32;
	my $offset = $parser->uint32;  # offset of the next chain command or 0
	my $mid_l = $parser->uint32;
	my $mid_h = $parser->uint32;
	my $aid_l = 0;
	my $aid_h = 0;
	my $tid   = 0;
	if ($flags & SMB::v2::Header::FLAGS_ASYNC_COMMAND) {
		$aid_l = $parser->uint32;
		$aid_h = $parser->uint32;
	} else {
		$parser->uint32;  # reserved (according to spec), not pid
		$tid = $parser->uint32;
	}
	my $uid_l = $parser->uint32;
	my $uid_h = $parser->uint32;
	my @sign  = $parser->bytes(16);
	my $struct_size = $parser->uint16;

	my $header = SMB::v2::Header->new(
		code      => $code,
		status    => $status,
		uid       => $uid_h << 32 + $uid_l,
		tid       => $tid,
		mid       => $mid_h << 32 + $mid_l,
		signature => \@sign,
		flags     => $flags,
		aid       => $aid_h << 32 + $aid_l,
		credits   => $credits,
		credit_charge => $credit_charge,
		struct_size => $struct_size,
	);

	my $command_name = $command_names[$code];
	my $command;

	if ($command_name) {
		my $command_class = "SMB::v2::Command::$command_name";
		my $command_filename = "SMB/v2/Command/$command_name.pm";
		require $command_filename unless $INC{$command_filename};

		$command = $command_class->new($header)->parse($parser)
			or warn sprintf "Failed to parse SMB2 command 0x%x ($command_name)\n", $code;
	} else {
		warn sprintf "Got unexisting SMB2 command 0x%x\n", $code;
	}

	return $command;
}

1;
