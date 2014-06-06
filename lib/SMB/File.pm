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

use Time::HiRes qw(stat);
use POSIX qw(strftime);
use if (1 << 32 == 1), 'bigint';  # support native uint64 on 32-bit platforms

use Exporter 'import';
our @EXPORT_OK = qw(from_nttime to_nttime);

my $nttime_factor = 10_000_000;
my $nttime_offset = 11_644_473_600;

sub from_nttime ($) {
	my $nttime = shift || die;

	return $nttime / $nttime_factor - $nttime_offset;
}

sub to_nttime ($) {
	my $time = shift || die;

	return ($time + $nttime_offset) * $nttime_factor;
}

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my $filename = $options{local_filename};
	my @stat = $filename && -e $filename ? stat($filename) : ();
	my $root = $options{local_root};
	my $name = '~noname~';
	if ($root) {
		die "No local_root directory ($root)" unless -d $root;
		die "local_filename ($filename) not inside local_root ($root)"
			if $filename && $filename !~ /^\Q$root\E(.*)/;
		$name = $1 || '/';
	}

	my $self = $class->SUPER::new(
		name             => $name,
		creation_time    => @stat ? to_nttime($stat[10])  : 0,
		last_access_time => @stat ? to_nttime($stat[ 8])  : 0,
		last_write_time  => @stat ? to_nttime($stat[ 9])  : 0,
		change_time      => @stat ? to_nttime($stat[ 9])  : 0,
		allocation_size  => @stat ? $stat[11] * $stat[12] : 0,
		end_of_file      => @stat ? $stat[ 7]             : 0,
		attributes       => 0,
		%options,
	);

	return $self;
}

sub update ($$$$$$$$) {
	my $self = shift;

	$self->creation_time = shift;
	$self->last_access_time = shift;
	$self->last_write_time = shift;
	$self->change_time = shift;
	$self->allocation_size = shift;
	$self->end_of_file = shift;
	$self->attributes = shift;
}

sub to_string ($;$) {
	my $time = shift;
	my $format = shift || "%4Y-%2m-%2d %2H:%2M";

	return strftime($format, localtime $time);
}

sub ctime { from_nttime($_[0]->creation_time) }
sub atime { from_nttime($_[0]->last_access_time) }
sub wtime { from_nttime($_[0]->last_write_time) }
sub mtime { from_nttime($_[0]->change_time) }
sub ctime_string { to_string($_[0]->ctime, $_[1]) }
sub atime_string { to_string($_[0]->atime, $_[1]) }
sub wtime_string { to_string($_[0]->wtime, $_[1]) }
sub mtime_string { to_string($_[0]->mtime, $_[1]) }

1;
