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

package SMB::Command;

use parent 'SMB';

sub new ($$$%) {
	my $class = shift;
	my $smb  = shift || die "No smb attribute in $class constructor\n";
	my $name = shift || die "No name attribute in $class constructor\n";
	my %options = @_;

	my $self = {
		%options,
		smb  => $smb,
		name => $name,
	};

	bless $self, $class;
}

sub is ($$) {
	my $self = shift;
	my $name = shift || '';

	return $self->name eq $name;
}

sub is_smb1 ($) { $_[0]->smb <= 1 }
sub is_smb2 ($) { $_[0]->smb >= 2 }

1;
