#===============================================================================
#
#   Copyright (C) 1999 Graham THE Ollis <ollisg@wwa.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#===============================================================================

package Netl::PacketPopup;

use Netl;
use Netl::Packet;
use Netl::Dump;
use Tk;
use integer;

sub destroy {
	my $self = shift;
	undef $self->{'packet'};
	$self->{'window'}->destroy;
}

sub label {
	my $body = shift;
	$body->Label(
		'-text'	=> "$_[0]:",
		'-padx' => 1, '-pady' => 1,
		)->grid($body->Label(
		'-text'	=> $_[1],
		'-padx' => 1, '-pady' => 1,
		), '-sticky' => 'w');
}

sub new_from_file {
	my ($classname, $filename) = @_;
	my $data = Netl::Dump::readentire($filename);
	return new($classname, $data, $filename);
}

sub new {
	my $classname = shift;
	my $data = shift;
	my $filename = shift;

	warn "zero length data passed to Netl::PacketPopup::new" if length($data) == 0;

	my $packet = Netl::Packet->new($data);

	my $window = MainWindow->new;

 	my $self = {	'packet'	=> $packet,
			'window'	=> $window,
			'name'		=> $filename,
		};
	bless($self, $classname);

	my $class = $packet->hw_class;
	$class = $packet->ip_class if $packet->is_ip;
	$window->title($filename);

	my $mb = $window->Frame->pack('-side' => 'top', '-fill' => 'x');
	my $file_mb = $mb->Menubutton(
			'-text'	=> 'File',
			'-relief' => 'raised',
			'-borderwidth' => 2,
		)->pack('-side' => 'left');

	$file_mb->command(
		'-label'	=> 'About',
		'-underline'	=> 0,
		'-command'	=> \&main::about_popup,
		);
	$file_mb->command(
		'-label'	=> 'Open',
		'-underline'	=> 0,
		'-command'	=> sub {
				my $fsref = $window->FileSelect
							('-directory' => '.',
							 '-filter' => '*.dg');
				my $file = $fsref->Show;
				Netl::PacketPopup->new_from_file($file);
			}
	);
	$file_mb->command(
		'-label'	=> 'Close',
		'-underline' => 0,
		'-command' => [ \&destroy, $self ]
	);
	$file_mb->command(
		'-label' => 'Quit',
		'-underline' => 0,
		'-command' => \&Netl::UI::quit
	);

	my $body = $window->Frame->pack;
	label($body, $class, sprintf("%s => %s", $packet->src, $packet->dst));

	my $tail = $window->Frame->pack;
	$tail->Button(
		'-text'   => 'MAC header',
		'-command' => [ \&mac_header_popup, $self ],
	)->grid($tail->Button(
			'-text' => 'raw',
			'-command' => [ \&hex_dump,
				$packet->mac_header,
				'MAC header for ' . $self->{'name'} ],
			),
		'-sticky' => 'nsew');
	if($packet->is_ip) {
		$tail->Button(
			'-text'   => 'IP header',
			'-command' => [ \&ip_header_popup, $self ],
		)->grid($tail->Button(
				'-text' => 'raw',
				'-command' => [ \&hex_dump,
					$packet->ip_header,
					'IP header for ' . $self->{'name'} ],
			),
			'-sticky' => 'nsew');
	}
	if($packet->is_tcp) {
		$tail->Button(
			'-text'   => 'TCP header',
			'-command' => [ \&tcp_header_popup, $self ],
		)->grid($tail->Button(
				'-text' => 'raw',
				'-command' => [ \&hex_dump,
					$packet->tcp_header,
					'TCP header for ' . $self->{'name'} ],
			),
			 '-sticky' => 'nsew');
	} elsif($packet->is_udp) {
		$tail->Button(
			'-text'   => 'UDP header',
			'-command' => [ \&udp_header_popup, $self ],
		)->grid($tail->Button(
				'-text' => 'raw',
				'-command' => [ \&hex_dump,
					$packet->udp_header,
					'UDP header for ' . $self->{'name'} ],
			),
			 '-sticky' => 'nsew');
	} elsif($packet->is_icmp) {
		$tail->Button(
			'-text'   => 'ICMP header',
			'-command' => [ \&icmp_header_popup, $self ],
		)->grid($tail->Button(
				'-text' => 'raw',
				'-command' => [ \&hex_dump,
					$packet->icmp_header,
					'ICMP header for ' . $self->{'name'} ],
			),
			 '-sticky' => 'nsew');
	}
	$tail->Label('-text'	=> 'payload')->grid(
	$tail->Button(
		'-text'	=> 'raw',
		'-command' => [ \&hex_dump, 
				$packet->{'payload'},
				'payload from ' . $self->{'name'} ],
		), '-sticky' => 'nsew');
	$tail->Label('-text'	=> 'full frame')->grid(
	$tail->Button(
		'-text'	=> 'raw',
		'-command' => [ \&hex_dump, 
				$packet->{'raw'},
				'ethernet frame from ' . $self->{'name'} ],
		), '-sticky' => 'nsew');

	return $self;
}

sub n {
	return sprintf("%x ($_[0])", $_[0]);
}

sub mac_header_popup {
	my $self = shift;
	my $packet = $self->{'packet'};
	my $window = MainWindow->new;
	my $body = $window->Frame->grid;
	$window->title('MAC header for ' . $self->{'name'});
	label($body, 'packet from', $self->{'name'});
	label($body, 'source', $packet->hw_src);
	label($body, 'destination', $packet->hw_dst);
	label($body, 'packet type', $packet->hw_class);
	$window->Button(
		'-text'		=> 'Ok',
		'-command'	=> sub { $window->destroy },
	)->grid;
}

sub ip_header_popup {
	my $self = shift;
	my $packet = $self->{'packet'};
	my $window = MainWindow->new;
	my $body = $window->Frame->grid;
	$window->title('IP header for ' . $self->{'name'});
	label($body, 'packet from', $self->{'name'});
	label($body, 'source', $packet->src);
	label($body, 'destination', $packet->dst);
	label($body, 'version', $packet->{'ip.version'});
	label($body, 'header length', n($packet->ip_len));
	label($body, 'tos', $packet->ip_tos);
	label($body, 'total length', n($packet->{'ip.tot_len'}));
	label($body, 'frag id', n($packet->{'ip.id'}));
	label($body, 'frag offset', n($packet->{'ip.frag_off'}));
	label($body, 'time to live', n($packet->{'ip.ttl'}));
	label($body, 'protocol', $packet->ip_class);
	$window->Button(
		'-text'		=> 'Ok',
		'-command'	=> sub { $window->destroy },
	)->grid;
}

sub tcp_header_popup {
	my $self = shift;
	my $packet = $self->{'packet'};
	my $window = MainWindow->new;
	my $body = $window->Frame->grid;
	my @flags = $packet->tcp_flags;
	$window->title('TCP header for ' . $self->{'name'});
	label($body, 'packet from', $self->{'name'});
	label($body, 'source', $packet->src);
	label($body, 'destination', $packet->dst);
	label($body, 'sequence number', n($packet->{'tcp.seq'}));
	label($body, 'ack number', n($packet->{'tcp.ack_seq'}));
	label($body, 'doff', n($packet->{'tcp.doff'}));
	label($body, 'frags', "@flags");
	label($body, 'window size', n($packet->{'tcp.window'}));
	label($body, 'urg pointer', n($packet->{'tcp.urg_ptr'}));
	$window->Button(
		'-text'		=> 'Ok',
		'-command'	=> sub { $window->destroy },
	)->grid;
}

sub udp_header_popup {
	my $self = shift;
	my $packet = $self->{'packet'};
	my $window = MainWindow->new;
	my $body = $window->Frame->grid;
	$window->title('UDP header for ' . $self->{'name'});
	label($body, 'packet from', $self->{'name'});
	label($body, 'source', $packet->src);
	label($body, 'destination', $packet->dst);
	label($body, 'len', n($packet->{'udp.len'}));
	label($body, 'check', n($packet->{'udp.check'}));
	$window->Button(
		'-text'		=> 'Ok',
		'-command'	=> sub { $window->destroy },
	)->grid;
}

sub icmp_header_popup {
	my $self = shift;
	my $packet = $self->{'packet'};
	my $window = MainWindow->new;
	my $body = $window->Frame->grid;
	$window->title('ICMP header for ' . $self->{'name'});
	label($body, 'packet from', $self->{'name'});
	label($body, 'source', $packet->src);
	label($body, 'destination', $packet->dst);

	label($body, 'type', $packet->icmp_type);
	label($body, 'code', $packet->icmp_code);
	label($body, 'id', $packet->{'icmp.id'});
	label($body, 'sequence', $packet->{'icmp.sequence'});
	label($body, 'gateway', $packet->{'icmp.gateway'});
	$window->Button(
		'-text'		=> 'Ok',
		'-command'	=> sub { $window->destroy },
	)->grid;
}

sub hex_dump {
	my $data = shift;
	my $title = shift;

	my $mw = MainWindow->new;
	$mw->title($title);
	my $t = $mw->Scrolled('Text');
	my $text = '';
	$t->pack('-expand' => 1, '-fill' => 'both');

	$f = $mw->Frame->pack;
	$f->Button('-text' => 'Ok', '-command' => sub { $mw->destroy })
		->grid(
	$f->Button(	'-text' => 'Save', 
			'-command' => sub { 
				$fsref = $mw->FileSelect('-directory' => '.');
				$file = $fsref->Show;
				unless(open(FP, ">$file")) {
					Netl::UI::toss_error("could not open",
							$file, "$!");
					return;
				}
				print FP $text;
				close FP;
			}
		), '-stick' => 'nsew',
	);
	tie(*TEXT, 'Tk::Text', $t);

	print TEXT "$title\n";
	open(TMP, ">/tmp/Netl::PacketPopup.$$");
	Netl::Dump::_dumpdatafile($data, length($data), TMP);
	close TMP;
	open(TMP, "/tmp/Netl::PacketPopup.$$");
	while(<TMP>) { print TEXT; $text .= $_ }
	unlink "/tmp/Netl::PacketPopup.$$";
}

1;
