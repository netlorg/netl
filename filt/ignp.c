/*==============================================================================
| ip
|   parse an ip datagram
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

#include "netl/global.h"

#include "netl/filter.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/config.h"

#include "filt.h"

struct configlist req;

/*==============================================================================
| check ip
|=============================================================================*/

void
check(u8 *dg, size_t len)
{
	int i;
	iphdr *ip = (iphdr *) &dg[14];
	struct configitem *c;

	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(ip->version != IP_VERSION)
		return;

	if(ip->protocol != PROTOCOL_IGNP)
		return;

	for(i=0; i<req.index; i++) {

		c = &req.c[i];

		if(

			 all_packets						||
			 ip_packets

			)
			continue;

			if(c->action == ACTION_IGNORE)
				return;
			if(!*(c->action_done))
				c->actionf(dg, c, len);

	}
}

