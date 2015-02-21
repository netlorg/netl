/*==============================================================================
| httplog.c
|   log all http:// type requests to the standard logging mechanism
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
|  13 Dec 99  G. Ollis	created module, by request.
|=============================================================================*/

#include <stdio.h>

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/filter.h"
#include "netl/action.h"
#include "netl/config.h"
#include "netl/io.h"
#include "netl/resolve.h"

fun_prefix struct configlist req;

/*==============================================================================
| log http GET
| problems:
|	. only checks ports 80 and 8080.  httpd may live anywhere.
|	. doesn't log POST (though this would probably be easy enough to add)
|=============================================================================*/

#define HTTPD_MAX_PATH_LEN 1024

fun_prefix void
check(u8 *dg, size_t len)
{
	int i, n;	/* for loops */
 	iphdr *ip = (iphdr *) &dg[14];
	tcphdr *h = (tcphdr *) &dg[(IPIHL(ip->ihl_version) << 2) + 14];
	int payload_offset = (IPIHL(ip->ihl_version) << 2) + 14;  /* this isn't quite right. */
	char *payload = ((char *) ip) + payload_offset;
	char path[HTTPD_MAX_PATH_LEN];

	/* first check to see if we even have a TCP packet */
	if(((machdr*)dg)->type != MACTYPE_IPDG
	|| IPVER(ip->ihl_version) != IP_VERSION
	|| ip->protocol != PROTOCOL_TCP)
                return;

	/* then check the port.  note that httpd can run on *any* port
	|  so you may want to remove this check.  80 and 8080 are just
	| two common ports used by httpd */
	if(h->dest != ntohs(80)
	&& h->dest != ntohs(8080))
		return;

	/* next we want psh, ack packets only */
	if(h->fin != 0
	|| h->syn != 0
	|| h->rst != 0
	|| h->psh != 1
	|| h->ack != 1)
		return;

	/*log("here:%d fin:%d syn:%d rst:%d psh:%d ack:%d", ntohs(h->dest),
		h->fin, h->syn, h->rst, h->psh, h->ack);*/

	/* we may have a http URL request.  look for GET in the payload. */
	for(i=0; i<len - payload_offset; i++)
		if(payload[i] == 'G'
		&& payload[i+1] == 'E'
		&& payload[i+2] == 'T') {	/* we have a GET request */
			i+=4;
			/* copy the path into a null terminated buffer */
			for(n=0;
			   n<(HTTPD_MAX_PATH_LEN-1)
			&& i<len - payload_offset
			&& payload[i] != 0x20;
			   n++,i++)
				path[n] = payload[i];
			path[n] = 0;
			if(!memcmp("http://", path, 7) ||
                           !memcmp("ftp://", path, 6)) {

				log("URL %s:%d => %s (via proxy %s:%d)",
					ip2string(ip->saddr),
					ntohs(h->source),
					path,
					ip2string(ip->daddr),
					ntohs(h->dest));

                        } else if(h->dest == ntohs(80))
				log("URL %s:%d => http://%s%s",
					ip2string(ip->saddr),
					ntohs(h->source),
					ip2string(ip->daddr),
					path);
			else
				log("URL %s:%d => http://%s:%d%s",
					ip2string(ip->saddr),
					ntohs(h->source),
					ip2string(ip->daddr),
					ntohs(h->dest),
					path);
		}
}

#if BOOL_DYNAMIC_MODULES == 0
void
filt_httplog_register_symbols(void)
{
	register_symbol("filt/httplog.so", "req", &req);
	register_symbol("filt/httplog.so", "check", check);
}
#endif


