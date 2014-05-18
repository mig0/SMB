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

package SMB::File;

use parent 'SMB';

use POSIX qw(strftime);

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my $self = {
		name => '*noname*',
		ctime => 0,  # created
		atime => 0,  # last access
		mtime => 0,  # last modify
		wtime => 0,  # last write
		%options,
	};

	bless $self, $class;
}

sub mtime_string ($) {
	my $self = shift;

	return strftime("%4Y-%2m-%2d %2H:%2M", localtime $self->mtime);
}

1;
