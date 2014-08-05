# Games::Checkers, Copyright (C) 2014 Mikhael Goikhman, migo@cpan.org
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

use integer;

package SMB;

our $VERSION = 0.020;

use constant {
	STATUS_SUCCESS                  => 0x00000000,
	STATUS_PENDING                  => 0x00000103,
	STATUS_NOTIFY_ENUM_DIR          => 0x0000010c,
	STATUS_SMB_BAD_TID              => 0x00050002,
	STATUS_OS2_INVALID_LEVEL        => 0x007c0001,
	STATUS_NO_MORE_FILES            => 0x80000006,
	STATUS_INVALID_PARAMETER        => 0xc000000d,
	STATUS_NO_SUCH_DEVICE           => 0xc000000e,
	STATUS_NO_SUCH_FILE             => 0xc000000f,
	STATUS_END_OF_FILE              => 0xc0000011,
	STATUS_MORE_PROCESSING_REQUIRED => 0xc0000016,
	STATUS_NO_FREE_MEMORY           => 0xc0000017,
	STATUS_ACCESS_DENIED            => 0xc0000022,
	STATUS_BUFFER_TOO_SMALL         => 0xc0000023,
	STATUS_OBJECT_NAME_NOT_FOUND    => 0xc0000034,
	STATUS_OBJECT_NAME_COLLISION    => 0xc0000035,
	STATUS_OBJECT_PATH_NOT_FOUND    => 0xc000003a,
	STATUS_SHARING_VIOLATION        => 0xc0000043,
	STATUS_DELETE_PENDING           => 0xc0000056,
	STATUS_PRIVILEGE_NOT_HELD       => 0xc0000061,
	STATUS_DISK_FULL                => 0xc000007f,
	STATUS_FILE_IS_A_DIRECTORY      => 0xc00000ba,
	STATUS_BAD_NETWORK_NAME         => 0xc00000cc,
	STATUS_DIRECTORY_NOT_EMPTY      => 0xc0000101,
	STATUS_NOT_A_DIRECTORY          => 0xc0000103,
	STATUS_CANCELLED                => 0xc0000120,
	STATUS_CANNOT_DELETE            => 0xc0000121,
	STATUS_FILE_CLOSED              => 0xc0000128,
	STATUS_INVALID_LEVEL            => 0xc0000148,
	STATUS_FS_DRIVER_REQUIRED       => 0xc000019c,
	STATUS_NOT_A_REPARSE_POINT      => 0xc0000275,
};

sub new ($%) {
	my $class = shift;
	my %options = @_;

	my $self = {
		disable_log => $options{quiet},
		%options,
	};

	bless $self, $class;
}

sub log ($$@) {
	my $self = shift;
	my $is_err = shift;
	my $format = shift;
	return if $self->disable_log;
	print sprintf("%s $format\n", $is_err ? '!' : '*', @_);
}

sub msg ($@) { shift()->log(0, @_) }
sub err ($@) { shift()->log(1, @_); return }

my $MAX_DUMP_BYTES = 8 * 1024;
my $dump_line_format = "%03x | 00 53 54 52 49 4E 47 aa  aa aa aa aa aa aa       | _STRING. ......   |\n";

sub mem ($$;$) {
	my $self = shift;
	my $data = shift;
	my $label = shift || "Data dump";
	return if $self->disable_log;

	my $len = length($data);
	$self->msg(sprintf("%s (%lu bytes%s):", $label, $len, $len > $MAX_DUMP_BYTES ? ", shorten" : ""), @_);
	$len = $MAX_DUMP_BYTES if $len > $MAX_DUMP_BYTES;

	for (my $n = 0; $n < ($len + 15) / 16; $n++) {
		for (my $i = 0; $i < 16; $i++) {
			my $valid = $n * 16 + $i < $len;
			my $b = $valid ? ord(substr($data, $n * 16 + $i, 1)) : undef;
			substr($dump_line_format, 7 + $i * 3 + ($i >= 8), 2) = $valid ? sprintf("%02x", $b) : "  ";
			substr($dump_line_format, 58 + $i + ($i >= 8), 1) = $valid ? $b == 0 ? '_' : $b <= 32 || $b >= 127 || $b == 37 ? '.' : chr($b) : ' ';
		}
		printf $dump_line_format, $n;
	}
}

sub parse_share_uri ($$) {
	my $self = shift;
	my $share_uri = shift;

	unless ($share_uri) {
		$self->err("No share uri supplied");
		return;
	}
	unless ($share_uri =~ m~^([/\\])\1([\w.]+(?::\d+)?)\1([^/\\]+)(?:$|\1)~) {
		$self->err("Invalid share uri ($share_uri)");
		return;
	}

	return wantarray ? ($2, $3) : $share_uri;
}

our %dump_seen;
our $dump_is_newline = 1;
our $dump_level_limit = 7;
our $dump_array_limit = 20;
our $dump_string_limit = 50;

sub _dump_prefix ($) {
	my $level = shift;

	return "" unless $dump_is_newline;
	$dump_is_newline = 0;

	return " " x (4 * $level);
}

sub _dump_eol () {
   $dump_is_newline = 1;

   return "\n";
}

sub _dump_string ($) {
	my $value = shift;

	my $len = length($value);
	if ($len > $dump_string_limit) {
		my $llen = length($len);
		substr($value, $dump_string_limit - 3 - $llen) =
			"..+" . ($len - $dump_string_limit + 3 + $llen);
	}

	$value =~ s/([\\"])/\\$1/g;
	$value =~ s/([^\\" -\x7e])/sprintf("\\x%02x", ord($1))/ge;

	return $value;
}

sub _dump_value ($) {
	my $value = shift;
	my $level  = shift || 0;
	my $inline = shift || 0;

	return '' if $level >= $dump_level_limit;

	my $type = ref($value);
	my $dump = _dump_prefix($level);
	my $is_seen = $type && $dump_seen{$value};
	$dump_seen{$value} = 1 if $type;

	if (! $type) {
		$dump .= defined $value
			? $value =~ /^-?\d+$/ ||$inline == 2 && $value =~ /^-?\w+$/
				? $value : '"' . _dump_string($value) . '"'
			: 'undef';
	} elsif ($type eq 'ARRAY') {
		if ($is_seen) {
			$dump .= "ARRAY (seen)";
		} else {
			$dump .= "[" . _dump_eol();
			my @array = @$value > $dump_array_limit ? (@$value)[0 .. $dump_array_limit - 2] : @$value;
			foreach (@array) {
				$dump .= _dump_prefix($level + 1);
				$dump .= &_dump_value($_, $level + 1, 1);
				$dump .= "," . _dump_eol();
			}
			if (@$value > $dump_array_limit) {
				$dump .= _dump_prefix($level + 1);
				$dump .= "...[+" . (@$value - $dump_array_limit + 1) . "]," . _dump_eol();
			}
			$dump .= _dump_prefix($level) . "]";
		}
	} elsif ($type eq 'HASH') {
		if ($is_seen) {
			$dump .= "HASH (seen)";
		} else {
			$dump .= "{" . _dump_eol();
			my $idx = 0;
			my @keys = sort keys %$value;
			my $size = @keys;
			foreach my $key (@keys) {
				my $val = $value->{$key};
				last if ++$idx == $dump_array_limit && $size > $dump_array_limit;
				$dump .= _dump_prefix($level + 1);
				$dump .= &_dump_value($key, $level + 1, 2);
				$dump .= " => ";
				$dump .= &_dump_value($val, $level + 1, 1);
				$dump .= "," . _dump_eol();
			}
			if ($size > $dump_array_limit) {
				$dump .= _dump_prefix($level + 1);
				$dump .= "...[+" . ($size - $dump_array_limit + 1) . "]," . _dump_eol();
			}
			$dump .= _dump_prefix($level) . "}";
		}
	} elsif ($type eq 'REF') {
		$dump .= "REF";
	} elsif ($type eq 'CODE') {
		$dump .= "CODE";
	} elsif ($type eq 'GLOB') {
		$dump .= "GLOB";
	} elsif ($type eq 'SCALAR') {
		$dump .= "\\";
		$dump .= &_dump_value($$value, $level + 1, 1);
	} else {
		$dump .= "$type ";
		my $native_type;
		foreach ('SCALAR', 'ARRAY', 'HASH', 'CODE', 'GLOB') {
			$native_type = $_ if $value->isa($_);
		}
		die "Non-standard perl ref type to dump in $value\n" unless $native_type;

		$dump_seen{$value} = 0;
		bless($value, $native_type);
		$dump .= &_dump_value($value, $level, 1);
		bless($value, $type);
	}

	$dump .= _dump_eol() unless $inline;

	return $dump;

}

sub dump ($;$) {
	my $self = shift;
	my $level = 0;

	my $dump = _dump_value($self);

	%dump_seen = ();

	return $dump;
}

our $AUTOLOAD;

sub AUTOLOAD ($;@) {
	my $self = shift;
	my @params = @_;

	my $method = $AUTOLOAD;
	$method =~ s/.*://g;

	return if $method eq 'DESTROY';  # ignore DESTROY messages

	die "Calling method $method for non-object '$self'\n"
		unless ref($self);

	if (exists $self->{$method}) {
		# define this accessor method explicitely if not yet
		no strict 'refs';
		*{$AUTOLOAD} = sub {
			my $self = shift;
			warn "Skipping extraneous params (@_) on access of field '$method' in $self\n"
				if @_ > 1;
			$self->{$method} = shift if @_;
			return $self->{$method};
		} unless $self->can($AUTOLOAD);

		return *{$AUTOLOAD}->($self, @params);
	}

	die "Unknown method or field '$method' in $self\n";
}

1;

__END__
# ----------------------------------------------------------------------------

=head1 NAME

SMB - A humble SMB network protocol implementation in Perl

=head1 SYNOPSIS

	use SMB::Server;

	my $server = SMB::Server->new(port => 10445);
	$server->run;


	use SMB::Client;

	my $client = SMB::Client->new('//10.0.2.2/test',
		username => 'test',
		password => 'secret',
	);
	my $tree = $client->connect_tree;
	$tree = $client->connect_tree('/test2');

	for my $file ($tree->find("*.txt")) {
		printf "%-40s %s\n", $file->name, $file->mtime_string;
	}

=head1 ABSTRACT

Receive and send SMB commands.  SMB is a network protocol used for
providing shared access to files.  It stands for Server Message Block,
also called CIFS - Common Internet File System.

The work is in progress.

=head1 SEE ALSO

http://migo.sixbit.org/software/smb-perl/

=head1 AUTHOR

Mikhael Goikhman <migo@cpan.org>

