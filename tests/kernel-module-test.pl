#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use Socket6;

my %cmds = (noop => 1, add => 2, delete => 3, update => 4, add_call => 5, del_call => 6, add_stream => 7, del_stream => 8, packet => 9);
my %ciphers = ('null' => 1, 'aes-cm' => 2, 'aes-f8' => 3);
my %hmacs = ('null' => 1, 'hmac-sha1' => 2);
$| = 1;

open(F, "+> /proc/rtpengine/0/control") or die;
{
	my $x = select(F);
	$| = 1;
	select($x);
}

sub re_address {
	my ($fam, $addr, $port) = @_;

	$fam //= '';
	$addr //= '';
	$port //= 0;

	if ($fam eq 'inet' || $fam eq 'inet4') {
		return pack('V a4 a12 v v', 2, inet_aton($addr), '', $port, 0);
	}
	if ($fam eq 'inet6') {
		return pack('V a16 v v', 10, inet_pton(AF_INET6, $addr), $port, 0);
	}
	if ($fam eq '') {
		return pack('V a16 v v', 0, '', 0, 0);
	}

	die;
}
sub re_srtp {
	my ($h) = @_;
	no warnings;
	return pack('VV a16 a16 a256 Q VV', $ciphers{$$h{cipher}}, $hmacs{$$h{hmac}},
		@$h{qw(master_key master_salt mki last_index auth_tag_len mki_len)});
	use warnings;
}
sub rtpengine_message {
	my ($cmd, %args) = @_;

	my $ret = '';

	# amd64 alignment
	$ret .= pack('VV', $cmds{$cmd}, 0);
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{local_addr}}, $args{local_port});
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{expected_addr}}, $args{expected_port});
	#print(length($ret) . "\n");
	$ret .= pack('V', $args{mismatch} // 0);
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{src_addr}}, $args{src_port});
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{dst_addr}}, $args{dst_port});
	#print(length($ret) . "\n");
	$ret .= re_address(@{$args{mirror_addr}}, $args{mirror_port});
	#print(length($ret) . "\n");
	$ret .= pack('V', $args{stream_idx} // 0);
	#print(length($ret) . "\n");
	$ret .= re_srtp($args{decrypt});
	#print(length($ret) . "\n");
	$ret .= re_srtp($args{encrypt});
	#print(length($ret) . "\n");
	$ret .= pack('V', $args{ssrc} // 0);
	#print(length($ret) . "\n");
	$ret .= pack('CCCCCCCCCCCCCCCC V', 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0);
	#print(length($ret) . "\n");
	$ret .= pack('C CvV', $args{tos} // 0, $args{flags} // 0, 0, 0);
	#print(length($ret) . "\n");

	return $ret;
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

my $sleep = 10;

my @local = qw(inet4 192.168.1.194);
my @src = qw(inet 192.168.1.194);
my @dst = qw(inet 192.168.1.90);
#my @src = qw(inet6 2a00:4600:1:0:a00:27ff:feb0:f7fe);
#my @dst = qw(inet6 2a00:4600:1:0:6884:adff:fe98:6ac5);
my $dec = {cipher => 'null', hmac => 'null'};
my $enc = {cipher => 'null', hmac => 'null'};

my $ret;
my $msg;

# print("add 9876 -> 1234/6543\n");
# $ret = syswrite(F, rtpengine_message('add', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("add fail\n");
# $ret = syswrite(F, rtpengine_message('add', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, mirror_addr => \@dst, mirror_port => 6789, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("update 9876 -> 1234/6543 & 6789\n");
# $ret = syswrite(F, rtpengine_message('update', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, mirror_addr => \@dst, mirror_port => 6789, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("update 9876 -> 2345/7890 & 4321\n");
# $ret = syswrite(F, rtpengine_message('update', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 2345, dst_addr => \@dst, dst_port => 7890, mirror_addr => \@dst, mirror_port => 4321, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("add fail\n");
# $ret = syswrite(F, rtpengine_message('add', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, mirror_addr => \@dst, mirror_port => 6789, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("update 9876 -> 1234/6543\n");
# $ret = syswrite(F, rtpengine_message('update', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("delete\n");
# $ret = syswrite(F, rtpengine_message('delete', local_addr => \@local, local_port => 9876, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("delete fail\n");
# $ret = syswrite(F, rtpengine_message('delete', local_addr => \@local, local_port => 9876, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);

# print("update fail\n");
# $ret = syswrite(F, rtpengine_message('update', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, tos => 184, decrypt => $dec, encrypt => $enc)) // '-';
# print("ret = $ret, code = $!\n");
# sleep($sleep);





# print("creating one call\n");
# 
# $msg = rtpengine_message_call('add_call', 0, 'testing one two three');
# $ret = sysread(F, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, $idx1) = unpack("VV V a256", $msg);
# print("index is $idx1\n");
# 
# sleep($sleep);

# print("creating another call\n");
# 
# $msg = rtpengine_message_call('add_call', 0, 'one more test');
# $ret = sysread(F, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, $idx2) = unpack("VV V a256", $msg);
# print("index is $idx2\n");
# 
# sleep($sleep);

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

# print("creating a stream (call 2)\n");
# 
# $msg = rtpengine_message_stream('add_stream', $idx2, 0, 'call two test stream');
# $ret = sysread(F, $msg, length($msg)) // '-';
# #print("reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# my (undef, undef, undef, $sidx3) = unpack("VV VV a256", $msg);
# print("index is $sidx3\n");
# 
# sleep($sleep);

# for (1 .. 20) {
# 	print("delivering a packet\n");
# 
# 	$msg = rtpengine_message_packet('packet', $idx2, $sidx3, 'packet data bla bla ' . rand() . "\n");
# 	$ret = syswrite(F, $msg) // '-';
# 	#print("reply: " . unpack("H*", $msg) . "\n");
# 	print("ret = $ret, code = $!\n");
# 
# 	sleep($sleep);
# }

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

# print("deleting stream\n");
# 
# $msg = rtpengine_message_stream('del_stream', $idx2, $sidx3, '');
# $ret = syswrite(F, $msg) // '-';
# #print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# sleep($sleep);

# print("deleting call\n");
# 
# $msg = rtpengine_message_call('del_call', $idx1, '');
# $ret = syswrite(F, $msg) // '-';
# #print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# sleep($sleep);

# print("deleting call\n");
# 
# $msg = rtpengine_message_call('del_call', $idx2, '');
# $ret = syswrite(F, $msg) // '-';
# #print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
# print("ret = $ret, code = $!\n");
# 
# sleep($sleep);






print("creating call\n");

$msg = rtpengine_message_call('add_call', 0, 'test call');
$ret = sysread(F, $msg, length($msg)) // '-';
#print("reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

my (undef, undef, $idx1) = unpack("VV V a256", $msg);
print("index is $idx1\n");

sleep($sleep);



print("creating a stream\n");

$msg = rtpengine_message_stream('add_stream', $idx1, 0, 'test stream');
$ret = sysread(F, $msg, length($msg)) // '-';
#print("reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

my (undef, undef, undef, $sidx1) = unpack("VV VV a256", $msg);
print("index is $sidx1\n");

sleep($sleep);



print("add 9876 -> 1234/6543\n");
$ret = syswrite(F, rtpengine_message('add', local_addr => \@local, local_port => 9876, src_addr => \@src, src_port => 1234, dst_addr => \@dst, dst_port => 6543, tos => 184, decrypt => $dec, encrypt => $enc, stream_idx => $sidx1, flags => 0x20)) // '-';
print("ret = $ret, code = $!\n");
sleep($sleep);



print("deleting stream\n");

$msg = rtpengine_message_stream('del_stream', $idx1, $sidx1, '');
$ret = syswrite(F, $msg) // '-';
#print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

sleep($sleep);



print("deleting call\n");

$msg = rtpengine_message_call('del_call', $idx1, '');
$ret = syswrite(F, $msg) // '-';
#print("ret = $ret, code = $!, reply: " . unpack("H*", $msg) . "\n");
print("ret = $ret, code = $!\n");

sleep($sleep);




close(F);
