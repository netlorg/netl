/*==============================================================================
| udp4
|   udp a datagram and send the output to the right place. (IP 4)
|
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

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"

#include "filt.h"

fun_prefix struct configlist req;

/*==============================================================================
| check/log udp
|=============================================================================*/

fun_prefix void
check(u8 *dg, size_t len, int tid)
{
	int i;
	iphdr *ip = (iphdr *) &dg[14];
	udphdr *h = (udphdr *) &dg[(IPIHL(ip->ihl_version) << 2) + 14];
	struct configitem *c;

	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(IPVER(ip->ihl_version) != IP_VERSION)
		return;

 	if(ip->protocol != PROTOCOL_UDP)
		return;

	/*============================================================================
	| process the datagram, even if it is a valid comunication request.
	|===========================================================================*/

	for(i=0; i<req.index; i++) {

		c = &req.c[i];

		if(all_packets) continue;
		if(ip_packets) continue;
		if(tcp_and_udp_packets) continue;

		act(dg, c, len, tid);

	}
}

#if BOOL_DYNAMIC_MODULES == 0
void
filt_udp4_register_symbols(void)
{
	register_symbol("filt/udp4.so", "req", &req);
	register_symbol("filt/udp4.so", "check", check);
}
#endif


