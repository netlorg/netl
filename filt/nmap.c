/*==============================================================================
| simple detection measures for nmap
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
|  14 Dec 99  G. Ollis	attempted to create this module
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

struct configlist req;

/*==============================================================================
| do some simple checks for someone attempting to nmap us.
| known problems:
|	. it only works for the machine it's running, on, so it's no good
|	  running this on a gateway.
|	. needs to be set up properly
|	. the UDP port scan detection is easily defeatable
|=============================================================================*/

void
check(u8 *dg, size_t len)
{
	iphdr *ip = (iphdr *) &dg[14];
	tcphdr *h = (tcphdr *) &dg[(ip->ihl << 2) + 14];
	static int findtcpconnection(u32, u32, u32, u32);

	if(((machdr*)dg)->type != MACTYPE_IPDG
	|| ip->version != IP_VERSION)
		return;

	/* UDP port scan (nmap -sU) */
	/* note that it is trivial to modify nmap to use udp
	   packets of different sizes.  i believe the latest
	   version of nmap does this */
	if(ip->protocol == PROTOCOL_UDP
	&& len == 14 + (ip->ihl << 2) + sizeof(udphdr) + 18) {
		log("empty UDP packet %s:%d => %s:%d",
			ip2string(ip->saddr), ntohs(h->source),
			ip2string(ip->daddr), ntohs(h->dest));
	}

	if(ip->protocol == PROTOCOL_TCP) {

		/* connect() and stealth syn scan (nmap -sT and -sS) */
		if(h->fin == 0
		&& h->urg == 0
		&& h->psh == 0
		&& h->syn == 1
		&& h->ack == 0
		&& h->rst == 0) {
			log("syn (possible port scan) %s:%d => %s:%d",
					ip2string(ip->saddr), ntohs(h->source),
					ip2string(ip->daddr), ntohs(h->dest));
		}

		/* Stealth FIN scan (nmap -sF) */
		else if(h->fin == 1
		&& h->urg == 0
		&& h->psh == 0
		&& h->syn == 0
		&& h->ack == 0
		&& h->rst == 0) {
			if(findtcpconnection(ip->saddr, h->source, ip->daddr, h->dest))
				log("possible FIN scan %s:%d => %s:%d",
					ip2string(ip->saddr), ntohs(h->source),
					ip2string(ip->daddr), ntohs(h->dest));
		}

		/* Xmas Tree scan (nmap -sX) */
		else if(h->fin == 1
		&& h->urg == 1
		&& h->psh == 1
		&& h->syn == 0
		&& h->ack == 0
		&& h->rst == 0) {
			if(findtcpconnection(ip->saddr, h->source, ip->daddr, h->dest))
				log("possible XMAS Tree scan %s:%d => %s:%d",
					ip2string(ip->saddr), ntohs(h->source),
					ip2string(ip->daddr), ntohs(h->dest));
		}

		/* NULL scan (nmap -sN) */
		/* this could probably be improved */
		else if(h->fin == 0
		&& h->urg == 0
		&& h->psh == 0
		&& h->syn == 0
		&& h->ack == 0
		&& h->rst == 0) {
			if(findtcpconnection(ip->saddr, h->source, ip->daddr, h->dest))
				log("possible NULL scan %s:%d => %s:%d",
					ip2string(ip->saddr), ntohs(h->source),
					ip2string(ip->daddr), ntohs(h->dest));
		}

		/* ACK ping (nmap -sN) */
		else if(h->fin == 0
		&& h->urg == 0
		&& h->psh == 0
		&& h->syn == 0
		&& h->ack == 1
		&& h->rst == 0) {
			if(findtcpconnection(ip->saddr, h->source, ip->daddr, h->dest))
				log("possible ACK ping attempt %s:%d => %s:%d",
					ip2string(ip->saddr), ntohs(h->source),
					ip2string(ip->daddr), ntohs(h->dest));
		}

	}
}

static int
findtcpconnection(u32 saddr, u16 source, u32 daddr, u16 dest)
{
	char buffer[1026];
	FILE *fp;
	int i_care; /* actually, i don't */

	u32 saddr1, daddr1, source1, dest1;

	if((fp = fopen("/proc/net/tcp", "r")) == NULL) {
		err("could not open /proc/net/tcp, nmap detection will fail");
		return 0;
	}
	fgets(buffer, 1024, fp);
	while(!feof(fp)) {
		fscanf(fp, "%d:%X:%X%X:%X %X %X:%X %X:%X %X %d %d %d\n",
			&i_care, &saddr1, &source1, &daddr1, &dest1,
			&i_care, &i_care, &i_care,
			&i_care, &i_care, &i_care,
			&i_care, &i_care, &i_care);

		if(saddr == saddr1
		&& ntohs(source) == source1
		&& daddr == daddr1
		&& ntohs(dest) == dest1) {
			fclose(fp);
			return 0;
		}

		if(saddr == daddr1
		&& ntohs(source) ==  dest1
		&& daddr == saddr1
		&& ntohs(dest) == source1) {
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	return 1;
}
