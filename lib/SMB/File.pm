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
use Fcntl ':mode';
use POSIX qw(strftime);
use if (1 << 32 == 1), 'bigint';  # support native uint64 on 32-bit platforms

use Exporter 'import';
our @EXPORT_OK = qw(from_nttime to_nttime);

use constant {
	ATTR_READONLY            => 0x00000001,
	ATTR_HIDDEN              => 0x00000002,
	ATTR_SYSTEM              => 0x00000004,
	ATTR_DIRECTORY           => 0x00000010,
	ATTR_ARCHIVE             => 0x00000020,
	ATTR_DEVICE              => 0x00000040,
	ATTR_NORMAL              => 0x00000080,
	ATTR_TEMPORARY           => 0x00000100,
	ATTR_SPARSE_FILE         => 0x00000200,
	ATTR_REPARSE_POINT       => 0x00000400,
	ATTR_COMPRESSED          => 0x00000800,
	ATTR_OFFLINE             => 0x00001000,
	ATTR_NOT_CONTENT_INDEXED => 0x00002000,
	ATTR_ENCRYPTED           => 0x00004000,
};

my $nttime_factor = 10_000_000;
my $nttime_offset = 11_644_473_600;

sub from_nttime ($) {
	my $nttime = shift || return 0;

	return $nttime / $nttime_factor - $nttime_offset;
}

sub to_nttime ($) {
	my $time = shift || return 0;

	return ($time + $nttime_offset) * $nttime_factor;
}

sub from_ntattr ($) {
	my $attr = shift || return 0;

	return 0
		| ($attr & ATTR_NORMAL    ? S_IFREG : 0)
		| ($attr & ATTR_DIRECTORY ? S_IFDIR : 0)
		| ($attr & ATTR_DEVICE    ? S_IFCHR : 0)
		| ($attr & ATTR_READONLY  ? 0444 : 0666)
		;
}

sub to_ntattr ($) {
	my $mode = shift || return 0;

	return 0
		| (S_ISREG($mode) ? ATTR_NORMAL    : 0)
		| (S_ISDIR($mode) ? ATTR_DIRECTORY : 0)
		| (S_ISBLK($mode) ? ATTR_DEVICE    : 0)
		| (S_ISCHR($mode) ? ATTR_DEVICE    : 0)
		| ($mode & S_IWUSR ? 0 : ATTR_READONLY)
		;
}

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my $name = delete $options{name} // die "No name in constructor";
	$name =~ s!\\!\/!g;
	$name =~ s!/{2,}!/!g;
	$name =~ s!/$!!;
	my $root = $options{share_root};
	my $filename = undef;
	if ($root) {
		die "No share_root directory ($root)" unless -d $root;
		my $path = $name =~ m![^/]+/(.*)! ? $1 : '';
		$filename = $path eq '' ? "$root/$path" : $root;
	}
	my @stat = $filename && -e $filename ? stat($filename) : ();

	my $self = $class->SUPER::new(
		name             => $name,
		filename         => $filename,  # server-side file only
		creation_time    => @stat ? to_nttime($stat[10])  : 0,
		last_access_time => @stat ? to_nttime($stat[ 8])  : 0,
		last_write_time  => @stat ? to_nttime($stat[ 9])  : 0,
		change_time      => @stat ? to_nttime($stat[ 9])  : 0,
		allocation_size  => @stat ? $stat[11] * $stat[12] : 0,
		end_of_file      => @stat ? $stat[ 7]             : 0,
		attributes       => @stat ? to_ntattr($stat[ 2])  : 0,
		exists           => @stat ? 1 : 0,
		%options,
	);

	return $self;
}

sub update ($$$$$$$$) {
	my $self = shift;

	$self->creation_time(shift);
	$self->last_access_time(shift);
	$self->last_write_time(shift);
	$self->change_time(shift);
	$self->allocation_size(shift);
	$self->end_of_file(shift);
	$self->attributes(shift);

	$self->exists($self->creation_time ? 1 : 0);
}

sub is_directory ($) {
	my $self = shift;

	return $self->attributes & ATTR_DIRECTORY ? 1 : 0;
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
