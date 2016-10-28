#!/usr/bin/perl

use strict;
use warnings;
use Linux::Inotify2;
use AnyEvent::Loop;
use AnyEvent;
use Fcntl;

my $i = new Linux::Inotify2 or die;
$i->blocking(0);

$i->watch('/var/spool/rtpengine', IN_CLOSE_WRITE | IN_DELETE, \&handle_inotify) or die;
my $i_w = AnyEvent->io(fh => $i->fileno, poll => 'r', cb => sub { $i->poll });

AnyEvent::Loop::run();

exit;

my %metafiles;

sub handle_inotify {
	my ($e) = @_;
	my $fn = $e->{w}->{name} . '/' . $e->{name};
	my $mf = ($metafiles{$fn} //= { name => $fn });
	if ($e->IN_DELETE) {
		handle_delete($e, $fn, $mf);
	}
	elsif ($e->IN_CLOSE_WRITE) {
		handle_change($e, $fn, $mf);
	}
	else {
		print("unhandled inotify event on $fn\n");
	}
}

sub handle_change {
	my ($e, $fn, $mf) = @_;

	print("handling change on $fn\n");

	my $fd;
	open($fd, '<', $fn) or return;

	# resume from where we left of
	my $pos = $mf->{pos} // 0;
	seek($fd, $pos, 0);

	# read as much as we can
	my $buf;
	read($fd, $buf, 100000) or return;
	$mf->{pos} = tell($fd);
	close($fd);

	# read contents section by section
	while ($buf =~ s/^(.*?)\n//s) {
		my $key = $1;
		$buf =~ s/^(\d+):\n//s or die $buf;
		my $len = $1;
		my $val = substr($buf, 0, $len, '');
		$buf =~ s/^\n\n//s or die;

		if ($key =~ /^(CALL-ID|PARENT)$/) {
			$mf->{$key} = $val;
		}
		elsif ($key eq 'STREAM') {
			open_stream($mf, $val);
		}
	}
}

sub handle_delete {
	my ($e, $fn, $mf) = @_;

	print("handling delete on $fn\n");

	for my $sn (keys(%{$mf->{streams}})) {
		my $stream = $mf->{streams}->{$sn};
		# this needs to be done explicitly, otherwise the closure would keep
		# the object from being freed
		delete($stream->{watcher});
	}

	delete($mf->{streams});
	delete($metafiles{$fn});
}


sub open_stream {
	my ($mf, $stream) = @_;
	print("opening $stream for $mf->{'CALL-ID'}\n");
	my $fd;
	sysopen($fd, '/proc/rtpengine/0/calls/' . $mf->{PARENT} . '/' . $stream, O_RDONLY | O_NONBLOCK) or return;
	my $ref = { name => $stream, fh => $fd };
	$ref->{watcher} = AnyEvent->io(fh => $fd, poll => 'r', cb => sub { stream_read($mf, $ref) });
	$mf->{streams}->{$stream} = $ref;
	print("opened for reading $stream for $mf->{'CALL-ID'}\n");
}

sub stream_read {
	my ($mf, $ref) = @_;
	print("handling read event for $mf->{name} / $ref->{name}\n");
	while (1) {
		my $buf;
		my $ret = sysread($ref->{fh}, $buf, 65535);
		defined($ret) or return;
		if ($ret == 0) {
			print("eof on $ref->{name} for $mf->{'CALL-ID'}\n");
			delete($mf->{streams}->{$ref->{name}});
			return;
		}
		print("$ret bytes read from $ref->{name} for $mf->{'CALL-ID'}\n");
	}
}
