#!/usr/bin/perl

use strict;
use warnings;

my %cmds = (noop => 1, add_call => 5, del_call => 6, add_stream => 7, del_stream => 8, packet => 9);

open(F, "+> /proc/rtpengine/0/control") or die;
{
	my $x = select(F);
	$| = 1;
	select($x);
}

sub rtpengine_message_call {
	my ($cmd, $idx, $callid) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV V a256', $cmds{$cmd}, 0, $idx, $callid // '');

	while (length($ret) < 792) {
		$ret .= pack('v', 0);
	}

	return $ret;
}

sub rtpengine_message_stream {
	my ($cmd, $call_idx, $stream_idx, $stream_name) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV VV a256', $cmds{$cmd}, 0, $call_idx, $stream_idx, $stream_name // '');

	while (length($ret) < 792) {
		$ret .= pack('v', 0);
	}

	return $ret;
}

sub rtpengine_message_packet {
	my ($cmd, $call_idx, $stream_idx, $data) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV VV', $cmds{$cmd}, 0, $call_idx, $stream_idx);

	while (length($ret) < 792) {
		$ret .= pack('v', 0);
	}

	$ret .= $data;

	return $ret;
}

my $sleep = 1;

# print("creating one call\n");
# 
# my $msg = rtpengine_message_call('add_call', 0, 'testing one two three');
# my $ret = sysread(F, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, $idx1) = unpack("VV V a256", $msg);
# print("index is $idx1\n");
# 
# sleep($sleep);

print("creating another call\n");

my $msg = rtpengine_message_call('add_call', 0, 'one more test');
my $ret = sysread(F, $msg, length($msg)) // '-';
#print("reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

my (undef, undef, $idx2) = unpack("VV V a256", $msg);
print("index is $idx2\n");

sleep($sleep);

# print("creating a stream (call 1)\n");
# 
# $msg = rtpengine_message_stream('add_stream', $idx1, 0, 'call one test stream');
# $ret = sysread(F, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, undef, $sidx1) = unpack("VV VV a256", $msg);
# print("index is $sidx1\n");
# 
# sleep($sleep);
# 
# print("creating another stream (call 1)\n");
# 
# $msg = rtpengine_message_stream('add_stream', $idx1, 0, 'another one test stream');
# $ret = sysread(F, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, undef, $sidx2) = unpack("VV VV a256", $msg);
# print("index is $sidx2\n");
# 
# sleep($sleep);

print("creating a stream (call 2)\n");

$msg = rtpengine_message_stream('add_stream', $idx2, 0, 'call two test stream');
$ret = sysread(F, $msg, length($msg)) // '-';
#print("reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

my (undef, undef, undef, $sidx3) = unpack("VV VV a256", $msg);
print("index is $sidx3\n");

sleep($sleep);

while (1) {
	print("delivering a packet\n");

	$msg = rtpengine_message_packet('packet', $idx2, $sidx3, 'packet data bla bla ' . rand() . "\n");
	$ret = syswrite(F, $msg) // '-';
	#print("reply: " . unpack("H*", $msg) . "\n");
	print("ret = $ret, code = $!\n");

	sleep($sleep);
}

# print("deleting stream\n");
# 
# $msg = rtpengine_message_stream('del_stream', $idx1, $sidx1, '');
# $ret = syswrite(F, $msg) // '-';
# #print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# sleep($sleep);
# 
# print("deleting stream\n");
# 
# $msg = rtpengine_message_stream('del_stream', $idx1, $sidx2, '');
# $ret = syswrite(F, $msg) // '-';
# #print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# sleep($sleep);

print("deleting stream\n");

$msg = rtpengine_message_stream('del_stream', $idx2, $sidx3, '');
$ret = syswrite(F, $msg) // '-';
#print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

sleep($sleep);

# print("deleting call\n");
# 
# $msg = rtpengine_message_call('del_call', $idx1, '');
# $ret = syswrite(F, $msg) // '-';
# #print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# sleep($sleep);

print("deleting call\n");

$msg = rtpengine_message_call('del_call', $idx2, '');
$ret = syswrite(F, $msg) // '-';
#print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

sleep($sleep);

close(F);
