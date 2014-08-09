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
use Encode qw(encode);

use SMB::Crypt qw(des_crypt56 md4 hmac_md5);
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
		lm_response           => undef,
		ntlm_response         => undef,
		domain                => undef,
		host                  => undef,
		username              => undef,
		session_key           => undef,
		auth_completed        => undef,
		user_passwords        => {},
		parser => SMB::Parser->new,
		packer => SMB::Packer->new,
	);
}

sub set_user_passwords ($$) {
	my $self = shift;
	my $user_passwords = shift || die "No user passwords to set";

	die "User passwords should be HASH"
		unless ref($user_passwords) eq 'HASH';

	$self->user_passwords($user_passwords);
}

sub create_lm_hash ($) {
	my $password = substr(encode('ISO-8859-1', uc(shift // "")), 0, 14);
	$password .= "\0" x (14 - length($password));

	return join('', map {
		des_crypt56('KGS!@#$%', $_)
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

sub get_user_passwd_line ($$) {
	my $username = shift;
	my $password = shift;

	return "$username:" . join('',
		map { map { sprintf "%02x", ord($_) } split '', $_ }
		create_lm_hash($password), create_ntlm_hash($password)
	);
}

sub load_user_passwords_from_file ($$) {
	my $self = shift;
	my $filename = shift || die "No passwd file";

	open PASSWD, "<$filename" or return 0;
	my @lines = <PASSWD>;
	close PASSWD or return 0;

	my %user_passwords = map {
		s/^\s+//;
		s/\s+$//;
		my ($username, $hash_str) = split ':', $_;
		my @hash_bytes = ($hash_str || '') =~ /^[0-9a-f]{64}$/
			? map { chr(hex(substr($hash_str, $_ * 2, 2))) } 0 .. 31
			: ();
		$username && $username =~ /^\w[\w.+-]*$/ && @hash_bytes
			? ($username => [ join('', @hash_bytes[0 .. 15]), join('', @hash_bytes[16 .. 31]) ])
			: ();
	} grep !/^\s*#/, @lines;

	return 0 unless %user_passwords;

	$self->user_passwords(\%user_passwords);

	return 1;
}

sub is_user_authenticated ($) {
	my $self = shift;

#	my $lm_response   = $self->lm_response   || return $self->err("No lm_response from client");
	my $ntlm_response = $self->ntlm_response || return $self->err("No ntlm_response from client");

	my ($hmac, $client_data) = $ntlm_response =~ /^(.{16})(.+)$/s;
	return $self->err("Invalid short ntlm_response from client")
		unless $hmac;

	my $username = $self->username // return $self->err("No username from client");
	my $password = $self->user_passwords->{$username} // return $self->err("No user '$username' on server");
	my ($lm_hash, $ntlm_hash) = ref($password) eq 'ARRAY' ? @$password : ();

#	$lm_hash   ||= create_lm_hash($password);
	$ntlm_hash ||= create_ntlm_hash($password);
	my $ntlmv2_hash = create_ntlmv2_hash($ntlm_hash, $username, $self->client_domain);

	return $self->err("Failed password check for user '$username', client not authenticated")
		unless $hmac eq hmac_md5($self->server_challenge . $client_data, $ntlmv2_hash);

	return 1;
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
			$len = $len * $factor + ord(shift @$bytes);
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
	} elsif ($tag >= ASN1_CONTEXT && $tag <= ASN1_CONTEXT + 3) {
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
	} elsif ($tag >= ASN1_CONTEXT && $tag <= ASN1_CONTEXT + 3) {
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

sub process_spnego ($$%) {
	my $self = shift;
	my $buffer = shift // return;
	my %options = @_;

	my @bytes = split '', $buffer;
	return unless @bytes > 2;

	@parsed_context_values = ();
	my $struct = parse_asn1(\@bytes);
	return unless $struct;

	if (!defined $self->ntlmssp_supported || $options{is_initial}) {
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
		$self->client_domain($parser->reset($off1)->bytes($len1));
		$self->client_host  ($parser->reset($off2)->bytes($len2));
	} elsif (!defined $self->server_challenge) {
		return $self->err("No expected NTLMSSP_CHALLENGE")
			unless $parser->uint32 == NTLMSSP_CHALLENGE;
		my $len1 = $parser->uint16;
		my $off1 = $parser->skip(2)->uint32;
		$self->server_challenge($parser->reset(24)->bytes(8));
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
		my $llen = $parser->uint16;
		my $loff = $parser->skip(2)->uint32;
		my $nlen = $parser->uint16;
		my $noff = $parser->skip(2)->uint32;
		my $len1 = $parser->uint16;
		my $off1 = $parser->skip(2)->uint32;
		my $len2 = $parser->uint16;
		my $off2 = $parser->skip(2)->uint32;
		my $len3 = $parser->uint16;
		my $off3 = $parser->skip(2)->uint32;
		$self->client_challenge($parser->reset($noff + 28)->bytes(8));
		$self->lm_response  ($parser->reset($loff)->bytes($llen));
		$self->ntlm_response($parser->reset($noff)->bytes($nlen));
		$self->client_domain($parser->reset($off1)->str($len1));
		$self->username     ($parser->reset($off2)->str($len2));
		$self->client_host  ($parser->reset($off3)->str($len3));
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
			->bytes("\0" x 8)
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
		my $ntlm_response = "$hmac$client_data";
		my $nlen = 16 + $self->packer->size;  # hmac + client data

		my $lm_response = create_lmv2_response($ntlm_hash, $username, $domain, $self->server_challenge);

		$self->lm_response($lm_response);
		$self->ntlm_response($ntlm_response);

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
			->bytes($ntlm_response)
			->str($domain)
			->str($username)
			->str($host)
			->bytes($self->session_key)
		;

		$struct = [ ASN1_CONTEXT + 1, ASN1_SEQUENCE,
			[ ASN1_CONTEXT + 2, ASN1_BINARY, $self->packer->data ],
		];
	} elsif (!defined $self->auth_completed) {
		$self->auth_completed($self->is_user_authenticated ? 1 : 0);
		$struct = [ ASN1_CONTEXT + 1, ASN1_SEQUENCE,
			[ ASN1_CONTEXT, ASN1_ENUMERATED, SPNEGO_ACCEPT_COMPLETED ],
		] if $self->auth_completed;
	} else {
		$self->err("generate_spnego called after auth_completed");
	}

RETURN:
	return undef unless $struct;

	return join '', @{generate_asn1(@$struct)};
}

1;
