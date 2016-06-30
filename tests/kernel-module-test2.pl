#!/usr/bin/perl

use strict;
use warnings;

my %cmds = (noop => 1, add_call => 5, del_call => 6);

open(F, "+> /proc/rtpengine/0/control") or die;
{
	my $x = select(F);
	$| = 1;
	select($x);
}

sub rtpengine_message {
	my ($cmd, $idx, $callid) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV V a256', $cmds{$cmd}, 0, $idx, $callid // '');

	while (length($ret) < 792) {
		$ret .= pack('v', 0);
	}

	return $ret;
}

my $sleep = 5;

my $msg = rtpengine_message('add_call', 0, 'testing one two three');
my $ret = sysread(F, $msg, length($msg)) // '-';
#print("reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

my (undef, undef, $idx) = unpack("VV V a256", $msg);
print("index is $idx\n");

sleep(5);

$msg = rtpengine_message('del_call', $idx, '');
$ret = sysread(F, $msg, length($msg)) // '-';
#print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

close(F);
