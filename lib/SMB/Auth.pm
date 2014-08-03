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

package SMB::Auth;

use strict;
use warnings;

use parent 'SMB';

use bytes;
use Digest::MD4 qw(md4);
use Digest::HMAC_MD5 qw(hmac_md5);
use Sys::Hostname qw(hostname);
use Encode qw(encode);

use SMB::Parser;
use SMB::Packer;
use SMB::Time qw(to_nttime);

# Abstract Syntax Notation One (small subset)

use constant {
	ASN1_BINARY      => 0x04,
	ASN1_OID         => 0x06,
	ASN1_ENUMERATED  => 0x0a,
	ASN1_SEQUENCE    => 0x30,
	ASN1_APPLICATION => 0x60,
	ASN1_CONTEXT     => 0xa0,
};

# Generic Security Service API / Simple Protected Negotiation

use constant {
	OID_SPNEGO       => '1.3.6.1.5.5.2',
	OID_MECH_NTLMSSP => '1.3.6.1.4.1.311.2.2.10',

	SPNEGO_ACCEPT_COMPLETED  => 0,
	SPNEGO_ACCEPT_INCOMPLETE => 1,
};

# NTLMSSP mechanism

use constant {
	NTLMSSP_ID_STR => "NTLMSSP\0",

	NTLMSSP_NEGOTIATE => 1,
	NTLMSSP_CHALLENGE => 2,
	NTLMSSP_AUTH      => 3,
	NTLMSSP_SIGNATURE => 4,

	NTLMSSP_ITEM_TERMINATOR    => 0,
	NTLMSSP_ITEM_NETBIOSHOST   => 1,
	NTLMSSP_ITEM_NETBIOSDOMAIN => 2,
	NTLMSSP_ITEM_DNSHOST       => 3,
	NTLMSSP_ITEM_DNSDOMAIN     => 4,
	NTLMSSP_ITEM_TIMESTAMP     => 7,

	NTLMSSP_FLAGS_CLIENT => 0x60008215,
	NTLMSSP_FLAGS_SERVER => 0x628a8215,
};

sub new ($) {
	my $class = shift;

	return $class->SUPER::new(
		ntlmssp_supported     => undef,
		client_host           => undef,
		client_domain         => undef,
		server_challenge      => undef,
		server_host           => undef,
		server_netbios_host   => undef,
		server_netbios_domain => undef,
		server_dns_host       => undef,
		server_dns_domain     => undef,
		server_timestamp      => undef,
		client_challenge      => undef,
		domain                => undef,
		host                  => undef,
		username              => undef,
		session_key           => undef,
		auth_completed        => undef,
		parser => SMB::Parser->new,
		packer => SMB::Packer->new,
	);
}

# DES parts for SMB authentication, ported from samba auth/smbdes.c
# perm1[56], perm2[48], perm3[64], perm4[48], perm5[32], perm6[64],
# sc[16], sbox[8][4][16]

my $des_perm1 = [
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
];
my $des_perm2 = [
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
my $des_perm3 = [
	58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
	57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
];
my $des_perm4 = [
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
   16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
   24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
];
my $des_perm5 = [
	16,  7, 20, 21, 29, 12, 28, 17,
	 1, 15, 23, 26,  5, 18, 31, 10,
	 2,  8, 24, 14, 32, 27,  3,  9,
	19, 13, 30,  6, 22, 11,  4, 25,
];
my $des_perm6 = [
	40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25,
];
my @des_sc = ( 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 );
my @des_sbox = (
	[
		[ 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 ],
		[  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 ],
		[  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 ],
		[ 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 ],
	],
	[
		[ 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 ],
		[  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 ],
		[  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 ],
		[ 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 ],
	],
	[
		[ 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 ],
		[ 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 ],
		[ 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 ],
		[  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 ],
	],
	[
		[  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 ],
		[ 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 ],
		[ 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 ],
		[  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 ],
	],
	[
		[  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 ],
		[ 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 ],
		[  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 ],
		[ 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 ],
	],
	[
		[ 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 ],
		[ 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 ],
		[  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 ],
		[  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 ],
	],
	[
		[  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 ],
		[ 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 ],
		[  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 ],
		[  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 ],
	],
	[
		[ 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 ],
		[  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 ],
		[  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 ],
		[  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 ],
	]
);

sub xor_inplace ($$) {
	my $a1 = shift;
	my $a2 = shift;

	for my $i (0 .. @$a1 - 1) {
		$a1->[$i] ^= $a2->[$i];
	}
}

sub des_str_to_key {
	my @str = map { ord($_) } split('', $_[0]);

	my @key = (
		0                       | ($str[0] >> 1),
		(($str[0] & 0x01) << 6) | ($str[1] >> 2),
		(($str[1] & 0x03) << 5) | ($str[2] >> 3),
		(($str[2] & 0x07) << 4) | ($str[3] >> 4),
		(($str[3] & 0x0F) << 3) | ($str[4] >> 5),
		(($str[4] & 0x1F) << 2) | ($str[5] >> 6),
		(($str[5] & 0x3F) << 1) | ($str[6] >> 7),
		(($str[6] & 0x7F) << 0) | 0,
	);
	$_ <<= 1 for @key;

	return \@key;
}

sub des_str_to_key_str {
	my $str = shift;

	return join('', map { chr($_) } @{des_str_to_key($str)});
}

sub permute ($$) {
	my $a = shift;
	my $p = shift;

	return [ map { $a->[$_ - 1] } @$p ];
}

sub lshift ($$) {
	my $a = shift;
	my $count = shift() % @$a;

	@$a = ( @{$a}[$count .. @$a - 1], @{$a}[0 .. $count - 1] );
}

sub des_dohash ($$$) {
	my $arr = shift;
	my $key = shift;
	my $forw = shift;

	my $c = permute($key, $des_perm1);
	my $d = [ splice(@$c, 28) ];

	my @ki;
	for my $i (0 .. 15) {
		lshift($c, $des_sc[$i]);
		lshift($d, $des_sc[$i]);

		$ki[$i] = permute([ @$c, @$d ], $des_perm2);
	}

	my $l = permute($arr, $des_perm3);
	my $r = [ splice(@$l, 32) ];

	for my $i (0 .. 15) {
		my $er = permute($r, $des_perm4);

		xor_inplace($er, $ki[$forw ? $i : 15 - $i]);

		my @b;
		for my $j (0 .. 7) {
			$b[$j] = [];
			for my $k (0 .. 5) {
				$b[$j][$k] = $er->[$j * 6 + $k];
			}
		}

		for my $j (0 .. 7) {
			my $m = ($b[$j][0] << 1) | ($b[$j][5] << 0);
			my $n = ($b[$j][1] << 3) | ($b[$j][2] << 2) | ($b[$j][3] << 1) | ($b[$j][4] << 0);

			for my $k (0 .. 3) {
				$b[$j][$k] = $des_sbox[$j][$m][$n] & (1 << (3 - $k)) ? 1 : 0;
			}
		}

		my @cb;
		for my $j (0 .. 7) {
			for my $k (0 .. 3) {
				$cb[$j * 4 + $k] = $b[$j][$k];
			}
		}

		my $pcb = permute(\@cb, $des_perm5);

		xor_inplace($l, $pcb);

		($l, $r) = ($r, $l);
	}

	return permute([ @$r, @$l ], $des_perm6 );
}

sub des_crypt56 ($$;$) {
	my $arr = shift;
	my $str = shift;
	my $forw = shift // 1;

	my $key = des_str_to_key($str);

	my $arrb = [];
	my $keyb = [];
	for my $i (0 .. 63) {
		$arrb->[$i] = $arr->[$i / 8] & (1 << (7 - $i % 8)) ? 1 : 0;
		$keyb->[$i] = $key->[$i / 8] & (1 << (7 - $i % 8)) ? 1 : 0;
	}

	my $outb = des_dohash($arrb, $keyb, $forw);

	my $out = [ (0) x 8 ];
	for my $i (0 .. 63) {
		$out->[$i / 8] |= 1 << (7 - $i % 8)
			if $outb->[$i];
	}

	return join('', map { chr($_) } @$out);
}

sub create_lm_hash ($) {
	my $password = substr(encode('ISO-8859-1', uc(shift // "")), 0, 14);
	$password .= "\0" x (14 - length($password));

#	use Crypt::DES;
#	return join('', map {
#		Crypt::DES->new(des_str_to_key_str($_))->encrypt('KGS!@#$%')
#	} $password =~ /^(.{7})(.{7})$/);

	return join('', map {
		des_crypt56([ 0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 ], $_)
	} $password =~ /^(.{7})(.{7})$/);
}

sub create_ntlm_hash ($) {
	my $password = encode('UTF-16LE', shift // "");

	return md4($password);
}

sub create_lm_response ($$) {
	my $lm_hash = shift || die;
	my $server_challenge = shift;

	$lm_hash .= "\0" x (21 - length($lm_hash));

	return join('', map {
		des_crypt56([ map { ord($_) } split '', $server_challenge ], $_)
	} $lm_hash =~ /^(.{7})(.{7})(.{7})$/);
}

sub create_ntlmv2_hash ($$$) {
	my $ntlm_hash = shift || die;
	my $username = shift // '';
	my $domain = shift // '';

	return hmac_md5(encode('UTF-16LE', uc($username . $domain)), $ntlm_hash);
}

sub create_lmv2_response ($$$$) {
	return create_ntlmv2_response($_[0], $_[1], $_[2], $_[3], 8);
}

sub create_ntlmv2_response ($$$$;$) {
	my $ntlm_hash = shift;
	my $username = shift;
	my $domain = shift;
	my $server_challenge = shift;
	my $client_challenge_len = shift || 24;

	my $client_challenge = join('', map { chr(rand(0x100)) } 1 .. $client_challenge_len);
	my $ntlmv2_hash = create_ntlmv2_hash($ntlm_hash, $username, $domain);

	return hmac_md5($server_challenge . $client_challenge, $ntlmv2_hash) . $client_challenge;
}

my @parsed_context_values;

sub parse_asn1 {
	my $bytes = shift;

	my $tag = ord(shift @$bytes);
	my $len = ord(shift @$bytes);
	if ($len >= 0x80) {
		my $llen = $len - 0x80;
		my $factor = 1;
		$len = 0;
		for (1 .. $llen) {
			$len += $factor * ord(shift @$bytes);
			$factor *= 256;
		}
	}

	my @contents;
	my @bytes = splice(@$bytes, 0, $len);
	if ($tag == ASN1_BINARY) {
		@contents = (\@bytes);
	} elsif ($tag == ASN1_OID) {
		my $idx = 0;
		my $carry = 0;
		@contents = (join('.', map {
			my @i;
			if (0 == $idx++) { @i = (int($_ / 40), $_ % 40); }
			elsif ($_ >= 0x80) { $carry = $carry * 0x80 + $_ - 0x80; }
			else { @i = ($carry * 0x80 + $_); $carry = 0; }
			@i
		} map { ord($_) } @bytes));
	} elsif ($tag == ASN1_ENUMERATED) {
		die "Unsupported len=$len" unless $len == 1;
		@contents = map { ord($_) } @bytes;
	} elsif ($tag == ASN1_SEQUENCE || $tag == ASN1_APPLICATION) {
		push @contents, parse_asn1(\@bytes)
			while @bytes;
	} elsif ($tag >= ASN1_CONTEXT && $tag <= ASN1_CONTEXT + 2) {
		@contents = @{parse_asn1(\@bytes)};
		$parsed_context_values[$tag - ASN1_CONTEXT] //= \@contents;
	} else {
		warn sprintf "Unsupported asn1 tag 0x%x on parse\n", $tag;
	}

	return [ $tag, @contents ];
}

sub generate_asn1 {
	my $tag     = shift // die "No asn1 tag";
	my $content = shift // die "No asn1 tag content";

	my @bytes;
	if ($tag == ASN1_BINARY) {
		@bytes = split('', $content);
	} elsif ($tag == ASN1_OID) {
		my $idx = 0;
		my $id0;
		@bytes = map { chr($_) } map {
			0 == $idx++ ? ($id0 = $_) && () : 2 == $idx ? ($id0 * 40 + $_) : (
				$_ >= 1 << 28 ? (0x80 | (($_ >> 28) & 0x7f)) : (),
				$_ >= 1 << 21 ? (0x80 | (($_ >> 21) & 0x7f)) : (),
				$_ >= 1 << 14 ? (0x80 | (($_ >> 14) & 0x7f)) : (),
				$_ >= 1 <<  7 ? (0x80 | (($_ >>  7) & 0x7f)) : (),
				$_ & 0x7f
			)
		} split(/\./, $content);
	} elsif ($tag == ASN1_ENUMERATED) {
		@bytes = (chr($content));
	} elsif ($tag == ASN1_SEQUENCE || $tag == ASN1_APPLICATION) {
		do {
			push @bytes, @{generate_asn1(@$content)};
			$content = shift;
		} while $content;
	} elsif ($tag >= ASN1_CONTEXT && $tag <= ASN1_CONTEXT + 2) {
		@bytes = @{generate_asn1($content, @_)};
	} else {
		warn sprintf "Unsupported asn1 tag 0x%x on generate\n", $tag;
	}

	my $len = @bytes;
	my @sub_lens;
	while ($len >= 0x80) {
		push @sub_lens, $len % 256;
		$len /= 256;
	}
	my @len_bytes = @sub_lens ? (0x80 + @sub_lens + 1, $len, @sub_lens) : ($len);

	return [ (map { chr($_) } $tag, @len_bytes), @bytes ];
}

sub process_spnego ($$) {
	my $self = shift;
	my $bytes = shift || return;

	return unless @$bytes > 2;

	@parsed_context_values = ();
	my $struct = parse_asn1($bytes);
	return unless $struct;

	if (!defined $self->ntlmssp_supported) {
		my $value = $parsed_context_values[0];
		return $self->err("No expected spnego context value")
			unless ref($value) eq 'ARRAY' && shift @$value == ASN1_SEQUENCE;
		for (@$value) {
			return $self->ntlmssp_supported(1)
				if $_->[0] == ASN1_OID && $_->[1] eq OID_MECH_NTLMSSP;
		}
		return $self->ntlmssp_supported(0);
	}

	my $value = $parsed_context_values[2];
	my $ntlmssp_bytes = ref($value) eq 'ARRAY' && shift @$value == ASN1_BINARY
		? shift @$value
		: undef;
	my $parser = $self->parser;
	unless (defined $self->client_challenge) {
		return $self->err("No expected spnego context+2 value (ntlmssp)")
			unless $ntlmssp_bytes;
		$parser->set(join('', @$ntlmssp_bytes));
		return $self->err("No expected NTLMSSP id string")
			unless $parser->bytes(length(NTLMSSP_ID_STR)) eq NTLMSSP_ID_STR;
	}

	if (!defined $self->client_host) {
		return $self->err("No expected NTLMSSP_NEGOTIATE")
			unless $parser->uint32 == NTLMSSP_NEGOTIATE;
		$parser->skip(4);  # skip flags
		my $len1 = $parser->uint16;
		my $off1 = $parser->skip(2)->uint32;
		my $len2 = $parser->uint16;
		my $off2 = $parser->skip(2)->uint32;
		$self->client_domain($parser->reset($off1)->str($len1));
		$self->client_host  ($parser->reset($off2)->str($len2));
	} elsif (!defined $self->server_challenge) {
		return $self->err("No expected NTLMSSP_CHALLENGE")
			unless $parser->uint32 == NTLMSSP_CHALLENGE;
		my $len1 = $parser->uint16;
		my $off1 = $parser->skip(2)->uint32;
		$self->server_challenge(scalar $parser->reset(24)->bytes(8));
		$self->server_host($parser->reset($off1)->str($len1));
		my $itemtype;
		do {{
			$itemtype = $parser->uint16;
			$parser->uint16 == 8 && $self->server_timestamp($parser->uint64), next
				if $itemtype == NTLMSSP_ITEM_TIMESTAMP;
			my $str = $parser->str($parser->uint16);
			$self->server_netbios_host($str)
				if $itemtype == NTLMSSP_ITEM_NETBIOSHOST;
			$self->server_netbios_domain($str)
				if $itemtype == NTLMSSP_ITEM_NETBIOSDOMAIN;
			$self->server_dns_host($str)
				if $itemtype == NTLMSSP_ITEM_DNSHOST;
			$self->server_dns_domain($str)
				if $itemtype == NTLMSSP_ITEM_DNSDOMAIN;
		}} while ($itemtype != NTLMSSP_ITEM_TERMINATOR)
	} elsif (!defined $self->client_challenge) {
		return $self->err("No expected NTLMSSP_AUTH")
			unless $parser->uint32 == NTLMSSP_AUTH;
		$parser->skip(8);  # skip lm desc
		my $nlen = $parser->uint16;
		my $noff = $parser->skip(2)->uint32;
		my $len1 = $parser->uint16;
		my $off1 = $parser->skip(2)->uint32;
		my $len2 = $parser->uint16;
		my $off2 = $parser->skip(2)->uint32;
		my $len3 = $parser->uint16;
		my $off3 = $parser->skip(2)->uint32;
		$self->client_challenge(scalar $parser->reset($noff + 28)->bytes(8));
		$self->client_domain($parser->reset($off1)->str($len1));
		$self->client_host  ($parser->reset($off2)->str($len2));
		$self->username     ($parser->reset($off3)->str($len2));
	} elsif (!defined $self->auth_completed) {
		my $value = $parsed_context_values[0];
		return $self->err("No expected spnego context value (ACCEPT_COMPLETED)")
			unless ref($value) eq 'ARRAY' && shift @$value == ASN1_ENUMERATED;
		$self->auth_completed(shift @$value == SPNEGO_ACCEPT_COMPLETED ? 1 : 0);
	} else {
		$self->err("process_spnego called after auth_completed");
	}

	return 1;
}

sub generate_spnego ($%) {
	my $self = shift;
	my %options = @_;

	my $struct;

	if (!defined $self->ntlmssp_supported || $options{is_initial}) {
		$self->ntlmssp_supported(1);
		$struct = [ ASN1_APPLICATION,
			[ ASN1_OID, OID_SPNEGO ],
			[ ASN1_CONTEXT, ASN1_SEQUENCE,
				[ ASN1_CONTEXT, ASN1_SEQUENCE,
					[ ASN1_OID, OID_MECH_NTLMSSP ],
				],
			],
		];
		goto RETURN;
	}

	my @names = hostname =~ /^([^.]*+)\.?+(.*)$/;
	my $host   = $options{host}   || $names[0];
	my $domain = $options{domain} || $names[1];

	if (!defined $self->client_host) {
		$self->client_host($host);
		$self->client_domain($domain);

		$self->packer->reset
			->bytes(NTLMSSP_ID_STR)
			->uint32(NTLMSSP_NEGOTIATE)
			->uint32(NTLMSSP_FLAGS_CLIENT)
			->uint16(length($domain))
			->uint16(length($domain))
			->uint32(32)
			->uint16(length($host))
			->uint16(length($host))
			->uint32(32 + length($domain))
			->bytes($domain)
			->bytes($host)
		;
		$struct = [ ASN1_APPLICATION,
			[ ASN1_OID, OID_SPNEGO ],
			[ ASN1_CONTEXT, ASN1_SEQUENCE,
				[ ASN1_CONTEXT, ASN1_SEQUENCE,
					[ ASN1_OID, OID_MECH_NTLMSSP ],
				],
				[ ASN1_CONTEXT + 2, ASN1_BINARY, $self->packer->data ],
			],
		];
	} elsif (!defined $self->server_challenge) {
		$self->server_challenge(join('', map { chr(rand(0x100)) } 1 .. 8));
		$self->server_host($host);
		$self->server_netbios_host($host);
		$self->server_netbios_domain($domain);
		$self->server_dns_host($host);
		$self->server_dns_domain($domain);
		my $tlen = 32 + length(
			$self->server_netbios_host .
			$self->server_netbios_domain .
			$self->server_dns_host .
			$self->server_dns_domain
		) * 2;

		$self->packer->reset
			->bytes(NTLMSSP_ID_STR)
			->uint32(NTLMSSP_CHALLENGE)
			->uint16(length($self->server_host) * 2)
			->uint16(length($self->server_host) * 2)
			->uint32(56)
			->uint32(NTLMSSP_FLAGS_SERVER)
			->bytes($self->server_challenge)
			->uint64(0)  # reserved
			->uint16($tlen)
			->uint16($tlen)
			->uint32(56 + length($self->server_host) * 2)
			->bytes("\x06\x01\xb1\x1d\x00\x00\x00\x0f")  # version
			->str($self->server_host)
			->uint16(NTLMSSP_ITEM_NETBIOSDOMAIN)
			->uint16(length($self->server_netbios_domain) * 2)
			->str($self->server_netbios_domain)
			->uint16(NTLMSSP_ITEM_NETBIOSHOST)
			->uint16(length($self->server_netbios_host) * 2)
			->str($self->server_netbios_host)
			->uint16(NTLMSSP_ITEM_DNSDOMAIN)
			->uint16(length($self->server_dns_domain) * 2)
			->str($self->server_dns_domain)
			->uint16(NTLMSSP_ITEM_DNSHOST)
			->uint16(length($self->server_dns_host) * 2)
			->str($self->server_dns_host)
			->uint16(NTLMSSP_ITEM_TIMESTAMP)
			->uint16(8)
			->bytes([ "\0" x 8 ])
			->uint16(NTLMSSP_ITEM_TERMINATOR)
			->uint16(0)
		;

		$struct = [ ASN1_CONTEXT + 1, ASN1_SEQUENCE,
			[ ASN1_CONTEXT, ASN1_ENUMERATED, SPNEGO_ACCEPT_INCOMPLETE ],
			[ ASN1_CONTEXT + 1, ASN1_OID, OID_MECH_NTLMSSP ],
			[ ASN1_CONTEXT + 2, ASN1_BINARY, $self->packer->data ],
		];
	} elsif (!defined $self->client_challenge) {
		my $username = $options{username} || '';
		my $password = $options{password} || '';
		$domain = $options{domain} || 'MYGROUP';
		$self->client_challenge(join('', map { chr(rand(0x100)) } 1 .. 8));
		$self->username($username);
		$self->domain($domain);
		$self->session_key([ map { chr(rand(0x100)) } 1 .. 16 ]);

#		my $lm_hash   = $options{lm_password_hash}   || create_lm_hash($password);
		my $ntlm_hash = $options{ntlm_password_hash} || create_ntlm_hash($password);
		my $ntlmv2_hash = create_ntlmv2_hash($ntlm_hash, $self->username, $self->domain);

		$self->packer->reset
			->uint32(0x0101)    # header
			->uint32(0)         # reserved
			->uint64(to_nttime(time))
			->bytes($self->client_challenge)
			->uint32(0)         # unknown
			->uint16(NTLMSSP_ITEM_NETBIOSDOMAIN)
			->uint16(length($self->server_netbios_domain) * 2)
			->str($self->server_netbios_domain)
			->uint16(NTLMSSP_ITEM_NETBIOSHOST)
			->uint16(length($self->server_netbios_host) * 2)
			->str($self->server_netbios_host)
			->uint16(NTLMSSP_ITEM_DNSDOMAIN)
			->uint16(length($self->server_dns_domain) * 2)
			->str($self->server_dns_domain)
			->uint16(NTLMSSP_ITEM_DNSHOST)
			->uint16(length($self->server_dns_host) * 2)
			->str($self->server_dns_host)
			->uint16(NTLMSSP_ITEM_TIMESTAMP)
			->uint16(8)
			->uint64($self->server_timestamp || 0)
			->uint16(NTLMSSP_ITEM_TERMINATOR)
			->uint16(0)
		;

		my $client_data = $self->packer->data;
		my $hmac = hmac_md5($self->server_challenge . $client_data, $ntlmv2_hash);
		my $nlen = 16 + $self->packer->size;  # hmac + client data

		my $lm_response = create_lmv2_response($ntlm_hash, $username, $domain, $self->server_challenge);

		$self->packer->reset
			->bytes(NTLMSSP_ID_STR)
			->uint32(NTLMSSP_AUTH)
			->uint16(24)
			->uint16(24)
			->uint32(64)
			->uint16($nlen)
			->uint16($nlen)
			->uint32(88)
			->uint16(length($domain) * 2)
			->uint16(length($domain) * 2)
			->uint32(88 + $nlen)
			->uint16(length($username) * 2)
			->uint16(length($username) * 2)
			->uint32(88 + $nlen + length($domain) * 2)
			->uint16(length($host) * 2)
			->uint16(length($host) * 2)
			->uint32(88 + $nlen + length("$domain$username") * 2)
			->uint16(16)
			->uint16(16)
			->uint32(88 + $nlen + length("$domain$username$host") * 2)
			->uint32(NTLMSSP_FLAGS_CLIENT)
			->bytes($lm_response)
			->bytes($hmac)
			->bytes($client_data)
			->str($domain)
			->str($username)
			->str($host)
			->bytes($self->session_key)
		;

		$struct = [ ASN1_CONTEXT + 1, ASN1_SEQUENCE,
			[ ASN1_CONTEXT + 2, ASN1_BINARY, $self->packer->data ],
		];
	} elsif (!defined $self->auth_completed) {
		$self->auth_completed(1);
		$struct = [ ASN1_CONTEXT + 1, ASN1_SEQUENCE,
			[ ASN1_CONTEXT, ASN1_ENUMERATED, SPNEGO_ACCEPT_COMPLETED ],
		];
	} else {
		$self->err("generate_spnego called after auth_completed");
	}

RETURN:
	return undef unless $struct;

	return generate_asn1(@$struct);
}

1;
