/*==============================================================================
|   Copyright (C) 1997 Graham THE Ollis <ollisg@netl.org>
|
|   This program is free software; you can redistribute it and/or modify
|   it under the terms of the GNU General Public License as published by
|   the Free Software Foundation; either version 2 of the License, or
|   (at your option) any later version.
|
|   This program is distributed in the hope that it will be useful,
|   but WITHOUT ANY WARRANTY; without even the implied warranty of
|   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|   GNU General Public License for more details.
|
|   You should have received a copy of the GNU General Public License
|   along with this program; if not, write to the Free Software
|   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
|=============================================================================*/

/* the IP specific portions are for IPv4 only */

#define all_packets \
	(c->check_src_hw && memcmp(c->src_hw, dg +6, 6) != 0 )  ||\
	(c->check_dst_hw && memcmp(c->dst_hw, dg, 6) != 0 ) 	||\
	(c->check_src_hw_not && memcmp(c->src_hw_not, dg +6, 6) == 0) ||\
	(c->check_dst_hw_not && memcmp(c->dst_hw_not, dg, 6) == 0)

#define ip_packets \
	(c->check_src_ip && c->src_ip != (ip->saddr & c->src_ip_mask))	||\
	(c->check_dst_ip && c->dst_ip != (ip->daddr & c->dst_ip_mask))	||\
	(c->check_src_ip_not && c->src_ip_not == (ip->saddr & c->src_ip_not_mask))	||\
	(c->check_dst_ip_not && c->dst_ip_not == (ip->daddr & c->dst_ip_not_mask)) 

#define ip6_packets \
	(c->check_src_ip6 && memcmp(&c->src_ip6, &ip->saddr, 16)!=0)	||\
	(c->check_dst_ip6 && memcmp(&c->dst_ip6, &ip->daddr, 16)!=0)	||\
	(c->check_src_ip6_not && memcmp(&c->src_ip6, &ip->saddr, 16)==0)||\
	(c->check_dst_ip6_not && memcmp(&c->dst_ip6, &ip->daddr, 16)==0)

#define tcp_and_udp_packets \
	(c->check_src_prt_not && c->src_prt_not == h->source)	||\
	(c->check_dst_prt_not && c->dst_prt_not == h->dest)	||\
\
	(c->check_src_prt && (ntohs(h->source) > ntohs(c->src_prt1) ||\
				ntohs(h->source) < ntohs(c->src_prt2)))	||\
	(c->check_dst_prt && (ntohs(h->dest) > ntohs(c->dst_prt1) ||\
				ntohs(h->dest) < ntohs(c->dst_prt2)))


#define act(dg, ci, len) {						\
		int i;							\
		if(ci->actionmod == NULL)				\
			return;						\
		for(i=0; i<ci->num_actionmod; i++) {			\
			if(!*(ci->actionmod[i].action_done)) {		\
				ci->actionmod[i].action(dg, ci, len);	\
			}						\
		}							\
	}
