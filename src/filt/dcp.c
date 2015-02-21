/*==============================================================================
| dcp.c - discrete comunication protocol
|   optimized (and debugged) by Graham THE Ollis <ollisg@netl.org>
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
|
|  Date       Name	Revision
|  ---------  --------  --------
|  09 Mar 97  G. Ollis	created module
|=============================================================================*/

#include "netl/version.h"

#include <string.h>
#include <stdio.h>
#ifndef NO_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"

#include "netl/io.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"
#include "netl/options.h"
#include "netl/resolve.h"

static u32 lasthearid = 0;

fun_prefix struct configlist req;		/* unused */

extern int reload_config_file;
extern int netl_config_listenport;
#define listenport netl_config_listenport

static u8 localhardware[6] = {0, 0, 0, 0, 0, 0};

/*==============================================================================
| soundwave: jam that transmission!
| process a comunication request
|=============================================================================*/

fun_prefix void
check(u8 *dg, size_t len)
{
	iphdr		*ip = (iphdr *) &dg[14];
	udphdr		*h = (udphdr *) &dg[14 + (IPIHL(ip->ihl_version) << 2)];
	static char	message[255];
	int		size, offset;
	u32		id;
	u16		nsize;

	if(listenport == -1)
		return;
	
	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(IPVER(ip->ihl_version) != IP_VERSION)
		return;

	if(ip->protocol != PROTOCOL_UDP)
		return;

	if(h->dest != listenport)
		return;

	if(ip->saddr != LOCALHOST_IP || ip->daddr != LOCALHOST_IP)
		return;

	if(memcmp(dg, localhardware, 6) || memcmp(&dg[6], localhardware, 6))
		return;

	/*============================================================================
	| convert the udp packet in to a c string.
	| that's c string as in STANDARD ANSI C character array type STRING thing.
	| not "i'm a sorry ass microsoft lacky who's going to spend the rest of his
	| life playing silly games while graham takes over the world" c strings.
	|===========================================================================*/

	offset = sizeof(machdr) + sizeof(iphdr) + sizeof(udphdr);

	id = ntohl(*((u32 *) &dg[offset]));		offset += 4;
	if(id == lasthearid)
		return;
	lasthearid = id;
	nsize = ntohs(*((u16 *) &dg[offset]));	offset += 2;

	size = len - offset;
	if(nsize < size)
		size = nsize;

	if(size > 254)
		size = 254;
	memcpy(message, &dg[offset], size);
	message[size] = '\0';

	/*============================================================================
	| all comunication requests are logged, even if we ignore them
	|===========================================================================*/

	log("dcp[%d]: \"%s\"", id, message);

	if(!strncmp("netl:", message, 5)) {
		if(!strncmp("readconfig", &message[5], 10)) {

			reload_config_file = 1;

		} else 
			err("warning: unknown netl comunication request %s", &message[5]);
	}
}

#if BOOL_DYNAMIC_MODULES == 0
void
filt_dcp_register_symbols(void)
{
	register_symbol("filt/dcp.so", "req", &req);
	register_symbol("filt/dcp.so", "check", check);
}
#endif


