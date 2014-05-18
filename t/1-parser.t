#!/usr/bin/perl

use Test::More tests => 37;

use lib '../lib', 'lib';

use_ok('SMB::Parser');

my $parser = SMB::Parser->new("Hello, world");
isa_ok($parser, 'SMB::Parser');

my @expected = (
	[ 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100 ],
	[ 25928, 27756, 11375, 30496, 29295, 25708 ],
	[ 18533, 27756, 28460, 8311, 28530, 27748 ],
	[ 1819043144, 1998597231, 1684828783 ],
	[ 1214606444, 1865162871, 1869769828 ],

);

# test uint*
for my $n (1 .. @expected) {
	my $expected = $expected[$n - 1];
	my $suffix = $n == 1 ? '8' : $n == 2 ? '16' : $n == 3 ? '16_be' : $n == 4 ? '32' : $n == 5 ? '32_be' : die;
	my $method = "uint$suffix";
	$parser->reset;
	is($parser->{offset}, 0, "$n reset");
	for my $i (1 .. @$expected) {
		is($parser->$method(), $expected->[$i - 1], "$n $method $i");
	}
}
