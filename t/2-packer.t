#!/usr/bin/perl

use Test::More tests => 69;

use lib '../lib', 'lib';

use_ok('SMB::Packer');

my $packer = SMB::Packer->new;
isa_ok($packer, 'SMB::Packer');

my @uints = (
	[ 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100 ],
	[ 25928, 27756, 11375, 30496, 29295, 25708 ],
	[ 18533, 27756, 28460, 8311, 28530, 27748 ],
	[ 1819043144, 1998597231, 1684828783 ],
	[ 1214606444, 1865162871, 1869769828 ],
);

# test uint*
for my $n (1 .. @uints) {
	my $uints = $uints[$n - 1];
	my $suffix = $n == 1 ? '8' : $n == 2 ? '16' : $n == 3 ? '16_be' : $n == 4 ? '32' : $n == 5 ? '32_be' : die;
	my $method = "uint$suffix";
	$packer->reset;
	is($packer->{offset}, 0, "$n reset");
	for my $i (1 .. @$uints) {
		ok($packer->$method($uints->[$i - 1]), "$n $method $i");
	}
	is($packer->size, $suffix / 8 * @$uints, "$n size");
	is($packer->{offset}, $packer->size, "$n offset");
	is($packer->{data}, 'Hello, world', "$n data");
}

$packer->reset;
ok($packer->bytes('Hello'),      "bytes('Hello')");
is($packer->size, 5,             "size +5");
ok($packer->bytes(', world'),    "bytes(', world')");
is($packer->{offset}, 12,        "offset +7");
ok($packer->bytes('!'),          "bytes('!')");
is($packer->size, 13,            "size +1");

ok($packer->skip(1),             "skip(1)");
is($packer->{offset}, 14,        "offset +1");
ok($packer->store('mark'),       "store('mark')");
ok($packer->bytes(scalar localtime), "bytes(localtime)");
is($packer->{offset}, $packer->size, "offset end");
ok($packer->restore('mark'),     "restore('mark')");
is($packer->{offset}, 14,        "offset 14");
isnt($packer->{offset}, $packer->size, "offset !end");
ok($packer->bytes(' ' x 2000),   "bytes(' ' x 2000)");
is($packer->{offset}, 2014,      "offset +2000");
is($packer->{offset}, $packer->size, "offset end");
