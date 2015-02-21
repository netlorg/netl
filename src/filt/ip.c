/*==============================================================================
| ip
|   parse a IP datagram. (IP 4/6)
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

#include <string.h>

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/filter.h"
#include "netl/action.h"
#include "netl/config.h"

fun_prefix struct configlist req;

static filt_mod *ip4, *ip6;

fun_prefix void
construct(void)
{
	ip4 = lookup_filter("ip4", PROT_IP4);
	ip6 = lookup_filter("ip6", PROT_IP6);
}

/*==============================================================================
| check ?
|=============================================================================*/

fun_prefix void
check(u8 *dg, size_t len, int tid)
{
	iphdr *ip = (iphdr *) &dg[14];

	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(IPVER(ip->ihl_version) == 4)
		ip4->check(dg, len, tid);
	else if(IPVER(ip->ihl_version) == 6)
		ip6->check(dg, len, tid);
}

#if BOOL_DYNAMIC_MODULES == 0
void
filt_ip_register_symbols(void)
{
	register_symbol("filt/ip.so", "req", &req);
	register_symbol("filt/ip.so", "check", check);
	register_symbol("filt/ip.so", "construct", construct);
}
#endif


