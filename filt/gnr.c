/*==============================================================================
| icmp
|   parse an icmp datagram
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
#define mynet 0x0a0a0a00

/*==============================================================================
| check icmp
|=============================================================================*/

void
check(u8 *dg, size_t len)
{
	iphdr *ip = (iphdr *) &dg[14];
	union { icmphdr i; tcphdr t; udphdr u; } *h = (void *) &dg[(ip->ihl << 2) + 14];
	u32 us = searchbyname("local");

	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(ip->version != IP_VERSION)
		return;

	if(ip->daddr != us)
		return;

	if((ntohl(ip->saddr) & mynet) == mynet)
		return;

	if(ip->protocol == PROTOCOL_ICMP) {

		if(h->i.type == 8)
			log("ping %s => %s", ip2string(ip->saddr), ip2string(ip->daddr));
		if(h->i.type == 0)
			log("pong %s => %s",  ip2string(ip->saddr), ip2string(ip->daddr));
	}

	else if(ip->protocol == PROTOCOL_UDP) {

		if(ntohs(h->u.dest) >= 33434)
			log("traceroute %s => %s (%d)", ip2string(ip->saddr), ip2string(ip->daddr), ntohs(h->u.dest));

	}

	else if(ip->protocol == PROTOCOL_TCP && 
		h->t.fin == 0 &&
		h->t.syn == 1 &&
		h->t.rst == 0 &&
		h->t.psh == 0 &&
		h->t.ack == 0 &&
		h->t.urg == 0) {

		char *prot;

		switch(ntohs(h->t.dest)) {
			case 21 : prot = "ftp"; break;
			case 22 : prot = "ssh"; break;
			case 23 : prot = "telnet"; break;
			case 25 : prot = "smtp"; break;
			case 70 : prot = "gopher"; break;
			case 79 : prot = "finger"; break;
			case 80 : prot = "www"; break;
			case 109: prot = "pop2"; break;
			case 110: prot = "pop3"; break;
			case 113: prot = "auth"; break;

			default : 
				if(h->t.source)
					prot = "ftp reply";
				else
					prot = "unknown_tcp";
				break;
		}

		log("%s %s:%d => %s:%d", prot, 
				ip2string(ip->saddr), 
				ntohs(h->t.source),
				ip2string(ip->daddr),
				ntohs(h->t.dest));

	}

	else if(ip->protocol == PROTOCOL_TCP && 
		h->t.fin == 1 &&
		h->t.syn == 0 &&
		h->t.rst == 0 &&
		h->t.psh == 0 &&
		h->t.ack == 0 &&
		h->t.urg == 0) {

		log("fin %s:%d => %s:%d", 
			ip2string(ip->saddr), 
			ntohs(h->t.source),
			ip2string(ip->daddr),
			ntohs(h->t.dest));

	}

	else if(ip->protocol == PROTOCOL_TCP) { 

		/* nothing */

	}

	else if(ip->protocol == PROTOCOL_IGNP) {

		log("ignp %s => %s", 
			ip2string(ip->saddr), 
			ip2string(ip->daddr));

	}

	else {
		log("unknown %s => %s",
			ip2string(ip->saddr), 
			ip2string(ip->daddr));
	}
}

