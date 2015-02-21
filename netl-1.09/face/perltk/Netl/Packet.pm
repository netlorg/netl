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

package Netl::Packet;

use Netl;
use Netl::Resolve;
use integer;

%icmp_types = (
	0	=>	'echoreply',
	3	=>	'dest_unreach',
	4	=>	'source_quench',
	5	=>	'redirect',
	8	=>	'echo',
	11	=>	'time_exceeded',
	12	=>	'parameterprob',
	13	=>	'timestamp',
	14	=>	'timestampreply',
	15	=>	'info_request',
	16	=>	'info_reply',
	17	=>	'address',
	18	=>	'addressreply',
);

%icmp_codes = (
	0	=>	'net_unreach redir_net exc_ttl',
	1	=>	'host_unreach redir_host exc_fragtime',
	2	=>	'prot_unreach redir_netos',
	3	=>	'port_unreach redir_hosttos',
	4	=>	'frag_needed',
	5	=>	'sr_failed',
	6	=>	'net_unknown',
	7	=>	'host_unknown',
	8	=>	'host_isolated',
	9	=>	'net_ano',
	10	=>	'host_ano',
	11	=>	'net_unr_tos',
	12	=>	'host_unr_tos',
	13	=>	'pkt_filtered',
	14	=>	'prec_violation',
	15	=>	'prec_cutoff',
);

sub new {
	my $classname = shift;
	my $data = shift;
	my(@hwdst, @hwsrc, $type, $version_ihl, $tos, $tot_len, $id, $frag_off);
	my($saddr, $daddr, $protocol, $ttl);

	($hwdst[0], $hwdst[1], $hwdst[2], $hwdst[3], $hwdst[4], $hwdst[5],
	 $hwsrc[0], $hwsrc[1], $hwsrc[2], $hwsrc[3], $hwsrc[4], $hwsrc[5], 
	 $type, $version_ihl, $tos, $tot_len, $id, $frag_off,
	 $ttl, $protocol, $check, $saddr, $daddr,
	) = unpack	'CCCCCC' . 	# @hwdst
			'CCCCCC' .	# @hwsrc
			'nCCnnn' . 	# $type, $version/$ihl, $tos
			'CCnNN' ,	# ttl, protocol, check, saddr, daddr
			$data;
	my %ip = (); my %ip2 = ();
	if($type == 0x0800) {
		my $ihl = $version_ihl & 0xf;
		%ip = (
			'ip.version'	=> ($version_ihl & 0xf0)/16,
			'ip.ihl'	=> $ihl,
			'ip.tos'	=> $tos,
			'ip.tot_len'	=> $tot_len,
			'ip.id'		=> $id,
			'ip.frag_off'	=> $frag_off,
			'ip.ttl'	=> $ttl,
			'ip.protocol'	=> $protocol,
			'ip.saddr'	=> $saddr,
			'ip.daddr'	=> $daddr,
			'ip.check'	=> $check,
		);
		my $data_tmp = substr($data, 14+($ihl <<2));
		if($protocol == 0x06) {
			my ($source, $dest, $seq, $ack_seq, $flags,
				$window, $check, $urg_ptr) = 
			unpack	'nnNNn' .
				'nnn', $data_tmp;
			my %tcp_flags = ();
			$tcp_flags{'fin'} = 1 if $flags & 1;
			$tcp_flags{'syn'} = 1 if $flags & 2;
			$tcp_flags{'rst'} = 1 if $flags & 4;
			$tcp_flags{'psh'} = 1 if $flags & 8;
			$tcp_flags{'ack'} = 1 if $flags & 0x10;
			$tcp_flags{'urg'} = 1 if $flags & 0x20;
			%ip2 = (
				'ip.source'	=> $source,
				'ip.dest'	=> $dest,
				'tcp.source'	=> $source,
				'tcp.dest'	=> $dest,
				'tcp.seq'	=> $seq,
				'tcp.ack_seq'	=> $ack_seq,
				'tcp.flags'	=> $flags,
				'tcp._flags'	=> { %tcp_flags },
				'tcp.window'	=> $window,
				'tcp.check'	=> $check,
				'tcp.urg_ptr'	=> $urg_ptr,
				'tcp.doff'	=> ($flags / 0x1000) & 0xf,
			);
			$data_tmp = substr($data_tmp, 20);
		} elsif($protocol == 0x11) {
			my ($source, $dest, $len, $check) =
				unpack 'nnnn', $data_tmp;
			%ip2 = (
				'ip.source'	=> $source,
				'ip.dest'	=> $dest,
				'udp.source'	=> $source,
				'udp.dest'	=> $dest,
				'udp.len'	=> $len,
				'udp.check'	=> $check,
			);
			$data_tmp = substr($data_tmp, 8);
		} elsif($protocol == 0x01) {
			my ($type, $code, $checksum, $gateway) =
				unpack 'CCnN', $data_tmp;
			%ip2 = (
				'icmp.type'	=> $type,
				'icmp.code'	=> $code,
				'icmp.checksum'	=> $checksum,
				'icmp.gateway'	=> $gateway,
				'icmp.id'	=> ($gateway >> 16) & 0xffff,
				'icmp.sequence'	=> $gateway & 0xffff,
			);
			$data_tmp = substr($data_tmp, 8);
		}
		$ip{'payload'} = $data_tmp;
	}
	
 	my $self = {	'raw'		=> $data,
			'hw.dst'	=> [ @hwdst ],
			'hw.src' 	=> [ @hwsrc ],
			'hw.type'	=> $type,
			%ip, %ip2,
		};
	bless($self, $classname);
	return $self;
}

sub is_ip {
	my $self = shift;
	return ($self->{'hw.type'}) == 0x0800;
}

sub ip_class {
	my $self = shift;
	return 'icmp' if $self->{'ip.protocol'} == 0x01;
	return 'ignp' if $self->{'ip.protocol'} == 0x02;
	return 'tcp' if $self->{'ip.protocol'} == 0x06;
	return 'udp' if $self->{'ip.protocol'} == 0x11;
	return sprintf("unknown [%02x]", $self->{'ip.protocol'});
}

sub is_icmp { return $_[0]->{'ip.protocol'} == 0x01 }
sub is_ignp { return $_[0]->{'ip.protocol'} == 0x02 }
sub is_tcp { return $_[0]->{'ip.protocol'} == 0x06 }
sub is_udp { return $_[0]->{'ip.protocol'} == 0x11 }

sub has_port { return $_[0]->is_tcp || $_[0]->is_udp }

sub _hw2str { return sprintf("%02x:%02x:%02x:%02x:%02x:%02x", @_) }
sub _ip2str { return Netl::Resolve::ip2string($_[0]) }

sub hw_src { return _hw2str(@{$_[0]->{'hw.src'}}) }
sub hw_dst { return _hw2str(@{$_[0]->{'hw.dst'}}) }

sub ip_src { return _ip2str($_[0]->{'ip.saddr'}) }
sub ip_dst { return _ip2str($_[0]->{'ip.daddr'}) }

sub src { 
	my $self =shift;
	return $self->hw_src unless $self->is_ip;
	my $fred = _ip2str($self->{'ip.saddr'});
	$fred .= ':' . $self->{'ip.source'} if $self->has_port;
	return $fred;
}

sub dst { 
	my $self =shift;
	return $self->hw_dst unless $self->is_ip;
	my $fred = _ip2str($self->{'ip.daddr'});
	$fred .= ':' . $self->{'ip.dest'} if $self->has_port;
	return $fred;
}

sub hw_class {
	return 'IP datagram' if $_[0]->{'hw.type'} == 0x0800;
	return 'ARP request/reply' if $_[0]->{'hw.type'} == 0x0800;
	return 'RARP request/reply' if $_[0]->{'hw.type'} == 0x0800;
	return sprintf("unknown [%04x]", $_[0]->{'hw.type'});
}

sub ip_len {
	return $_[0]->{'ip.ihl'} << 2;
}

sub ip_tos {
	my $tos = $_[0]->{'ip.tos'};
	return 'none' if $tos == 0;
	return 'minimize delay' if $tos == 0x10;
	return 'maximize thruput' if $tos == 0x08;
	return 'maximize reliability' if $tos == 0x04;
	return 'minimize monitary cost' if $tos == 0x02;
	return sprintf("unknown [%02x]", $tos);
}

sub tcp_flags {
	return keys (%{$_[0]->{'tcp._flags'}});
}

sub icmp_type {
	return $icmp_types{$_[0]->{'icmp.type'}};
}

sub icmp_code {
	my $code = $_[0]->{'icmp.code'};
	return sprintf("%02x $icmp_codes{$code}", $code);
}

sub ip_header {
	return substr($_[0]->{'raw'}, 14, 20);
}

sub mac_header {
	return substr($_[0]->{'raw'}, 0, 14);
}

sub tcp_header {
	return substr($_[0]->{'raw'}, 14+($_[0]->{'ip.ihl'} <<2), 20);
}
sub udp_header {
	return substr($_[0]->{'raw'}, 14+($_[0]->{'ip.ihl'} <<2), 8);
}
sub icmp_header {
	return substr($_[0]->{'raw'}, 14+($_[0]->{'ip.ihl'} <<2), 8);
}

1;
