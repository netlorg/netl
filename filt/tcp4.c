/*==============================================================================
| tcp4
|   parse a tcp datagram. (IP 4)
|
|   Copyright (C) 1999 Graham THE Ollis <ollisg@netl.org>
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
|
|  Date       Name	Revision
|  ---------  --------  --------
|  26 sep 97  G. Ollis	took this code out of the main module and put it here
|			for safe keeping.
|=============================================================================*/

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"

#include "filt.h"

struct configlist req;

/*==============================================================================
| check tcp
|=============================================================================*/

void
check(u8 *dg, size_t len)
{
	int i;
	iphdr *ip = (iphdr *) &dg[14];
	tcphdr *h = (tcphdr *) &dg[(ip->ihl << 2) + 14];
	u8 flags=*(((char *) h) + 13);
	struct configitem *c;

	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(ip->version != IP_VERSION)
		return;

	if(ip->protocol != PROTOCOL_TCP)
		return;

	for(i=0; i<req.index; i++) {

		c = &req.c[i];

		if(all_packets) continue;
		if(ip_packets) continue;
		if(tcp_and_udp_packets)	continue;

		if(

			 /*=======================================================================
			 | flags must be correct
			 |======================================================================*/

			 (c->check_tcp_flags_on && 
					(flags & c->tcp_flags_on) != c->tcp_flags_on)		||
			 (c->check_tcp_flags_off && 
					(~flags & c->tcp_flags_off) != c->tcp_flags_off)

			)
			continue;

			act(dg, c, len);
	}
}

