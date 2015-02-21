/*==============================================================================
| log output module for netl
|   by Graham THE Ollis <ollisg@netl.org>
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
|  26 sep 97  G. Ollis	took this code out of the main module and put it here
|			for safe keeping.
|=============================================================================*/

#include <stdio.h>

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"
#include "netl/io.h"
#include "netl/resolve.h"

#ifdef BOOL_THREADED
fun_prefix int action_done[PTHR_MAXTHREADS];
#else
fun_prefix int action_done;
#endif
fun_prefix char *extra_string = "";

/*==============================================================================
| send output to either syslogd, or stdout
|=============================================================================*/

fun_prefix void
action(u8 *dg, struct configitem *cf, size_t len, int tid)
{
	iphdr *ip = (iphdr *) &dg[14];
	tcphdr *t = (tcphdr *) &dg[(IPIHL(ip->ihl_version) << 2) + 14];
	char *logname = cf->logname;
	if(logname == NULL)
		logname = "";

	#ifdef BOOL_THREADED
		action_done[tid] = TRUE;
	#else
		action_done = TRUE;
	#endif

	if(((machdr*)dg)->type == MACTYPE_IPDG && 
	   IPVER(ip->ihl_version) == IP_VERSION) {
		if(ip->protocol == PROTOCOL_TCP || ip->protocol == PROTOCOL_UDP) {

			log("%s %s:%d => %s:%d (%s)", 
				logname, 
				ip2string(ip->saddr), 
				ntohs(t->source), 
				ip2string(ip->daddr), 
				ntohs(t->dest), 
				extra_string);

		} else {

			log("%s %s => %s (%s)",
				logname,
				ip2string(ip->saddr),
				ip2string(ip->daddr),
				extra_string);

		}
	} else {

		log("%s %02x:%02x:%02x:%02x:%02x:%02x => %02x:%02x:%02x:%02x:%02x:%02x (%s)",
	                logname, dg[6], dg[7], dg[8], dg[9], dg[10], dg[11], dg[0], dg[1], dg[2], dg[3], dg[4], dg[5],
			extra_string);

	}
}

#if BOOL_DYNAMIC_MODULES == 0
void
out_log_register_symbols(void)
{
	register_symbol("out/log.so", "action_done", &action_done);
	register_symbol("out/log.so", "action", action);
	register_symbol("out/log.so", "extra_string", &extra_string);
}
#endif


