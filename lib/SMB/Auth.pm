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
use Sys::Hostname qw(hostname);
use SMB::Parser;
use SMB::Packer;

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
	OID_SPNEGO       => [ 43, 6, 1, 5, 5, 2 ],
	OID_MECH_NTLMSSP => [ 43, 6, 1, 4, 1, 311, 2, 2, 10 ],

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

	NTLMSSP_FLAGS_CLIENT => 0x60088215,
	NTLMSSP_FLAGS_SERVER => 0x628a8215,
};

# internal states

use constant {
	STATE_INIT => 0,
	STATE_SPNEGO_SUPPORTED => 1,
	STATE_NEGOTIATE => 2,
	STATE_CHALLENGE => 3,
	STATE_AUTH => 4,
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
		my $carry = 0;
		@contents = ([ map { my @i; if ($_ >= 0x80) { $carry = $carry * 0x80 + $_ - 0x80; } else { @i = ($carry * 0x80 + $_); $carry = 0; } @i } map { ord($_) } @bytes ]);
	} elsif ($tag == ASN1_ENUMERATED) {
		die "Unsupported len=$len" unless $len == 1;
		@contents = @bytes;
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
		@bytes = map { chr($_) } map { $_ >= 0x80 ? (0x80 + int($_ / 0x80), $_ % 0x80) : $_ } @$content;
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
				if $_->[0] == ASN1_OID && join('.', @{$_->[1]}) eq join('.', @{OID_MECH_NTLMSSP()});
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
		$self->server_challenge([ $parser->reset(24)->bytes(8) ]);
		$self->server_host($parser->reset($off1)->str($len1));
		my $itemtype;
		do {
			$itemtype = $parser->uint16;
			my $str = $parser->str($parser->uint16);
			$self->server_netbios_host($str)
				if $itemtype == NTLMSSP_ITEM_NETBIOSHOST;
			$self->server_netbios_domain($str)
				if $itemtype == NTLMSSP_ITEM_NETBIOSDOMAIN;
			$self->server_dns_host($str)
				if $itemtype == NTLMSSP_ITEM_DNSHOST;
			$self->server_dns_domain($str)
				if $itemtype == NTLMSSP_ITEM_DNSDOMAIN;
		} while ($itemtype != NTLMSSP_ITEM_TERMINATOR)
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
		$self->client_challenge([ $parser->reset($noff + 28)->bytes(8) ]);
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
		$self->server_challenge([ map { chr(rand(0x100)) } 1 .. 8 ]);
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
		$self->client_challenge([ map { chr(rand(0x100)) } 1 .. 8 ]);
		$self->username($username);
		$self->session_key([ map { chr(rand(0x100)) } 1 .. 16 ]);
		my $nlen = 76 + length(
			$self->server_netbios_host .
			$self->server_netbios_domain .
			$self->server_dns_host .
			$self->server_dns_domain
		) * 2;

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
			->bytes("\1" x 24)
			->bytes("\2" x 16)  # HMAC
			->uint32(0x0101)    # header
			->uint32(0)         # reserved
			->uint64(0)         # time
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
			->bytes([ "\0" x 8 ])
			->uint16(NTLMSSP_ITEM_TERMINATOR)
			->uint16(0)
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
