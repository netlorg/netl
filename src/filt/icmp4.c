/*==============================================================================
| icmp
|   parse an icmp datagram (IP 4)
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
|=============================================================================*/

#include <stdio.h>
#include <sys/types.h>

#include "netl/global.h"

#include "netl/filter.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/config.h"

fun_prefix struct configlist req;

#include "filt.h"

/*==============================================================================
| check icmp
|=============================================================================*/

fun_prefix void
check(u8 *dg, size_t len, int tid)
{
	int i;
	iphdr *ip = (iphdr *) &dg[14];
	icmphdr *h = (icmphdr *) &dg[(IPIHL(ip->ihl_version) << 2) + 14];
	struct configitem *c;

	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(IPVER(ip->ihl_version) != IP_VERSION)
		return;

	if(ip->protocol != PROTOCOL_ICMP)
		return;

	for(i=0; i<req.index; i++) {

		c = &req.c[i];

		if(

			 all_packets					||
			 ip_packets					||

			 /*=======================================================================
			 | must be the correct type
			 |======================================================================*/

			 (c->check_icmp_type && c->icmp_type != h->type)||
			 (c->check_icmp_code && c->icmp_code != h->code)

			)
			continue;

			act(dg, c, len, tid);

	}
}

#if BOOL_DYNAMIC_MODULES == 0
void
filt_icmp4_register_symbols(void)
{
	register_symbol("filt/icmp4.so", "req", &req);
	register_symbol("filt/icmp4.so", "check", check);
}
#endif


