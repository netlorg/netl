/*==============================================================================
| ping
|   log pings (ICMP_ECHO) and pongs (ICMP_ECHOREPLY)
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@wwa.com>
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

#include "netl/global.h"

#include "netl/filter.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/config.h"
#include "netl/io.h"
#include "netl/resolve.h"

struct configlist req;

/*==============================================================================
| check icmp
|=============================================================================*/

void
check(u8 *dg, size_t len)
{
	iphdr *ip = (iphdr *) &dg[14];
	icmphdr *h = (icmphdr *) &dg[(ip->ihl << 2) + 14];

	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(ip->version != IP_VERSION)
		return;

	if(ip->protocol != PROTOCOL_ICMP)
		return;

	if(h->type == 8)
		log("ping %s => %s", ip2string(ip->saddr), ip2string(ip->daddr));
	if(h->type == 0)
		log("pong %s => %s",  ip2string(ip->saddr), ip2string(ip->daddr));
}

