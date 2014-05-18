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

package SMB::v1::Command;

use parent 'SMB::Command';

sub new ($%) {
	my $class = shift;
	my %options = @_;

	die "Invalid sub-class $class, should be SMB::v1::Command::*"
		unless $class =~ /^SMB::v1::Command::(\w+)/;

	my $self = $class->SUPER::new(
		1, $1,
		%options,
	);

	return $self;
}

1;
