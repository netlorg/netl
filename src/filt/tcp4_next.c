/*==============================================================================
| tcp4_next
|   parse a tcp datagram. (IP 4).  check falgs on first packet, but not next x.
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
|  02 jul 99  G. Ollis	modified from generic tcp4 filter.
|			added signature for keeping track of what we need to
|			do our stuff.
|=============================================================================*/

/* there are several improvements which could be made on this module, which
   are left as an excersize to the curious.

   .  only twenty connections (as defined by a constant below) can be
      `nexted.' one way to improve this number is to use a dynamic
      structure, which will reduce the efficency of this module.

   .  the number of packets to be acted on is defined as a constant in
      this module.  it should be trivial to add a next= option in netl.  
      i have chosen not to do this for now, since this is still very much
      an unofficial module.

*/

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"

#include "filt.h"

struct configlist req;

#define COUNT		5
#define NUM_SIGS	20

typedef struct {
	u32	saddr, daddr;	/* address */
	u16	source, dest;	/* port */
	int	count;
	int	free;
} signature;

signature sig[NUM_SIGS];

/*==============================================================================
| initalize signatures
|=============================================================================*/

void
construct(void)
{
	int i;
	for(i=0; i<NUM_SIGS; i++) {
		sig[i].free = TRUE;
	}
}

/*==============================================================================
| allocate a new sig.  NOTE: this may preempt an entry, if there are none free!
|=============================================================================*/

int next_preempt = 0;

int
newsig(void)
{
	int i;
	for(i=0; i<NUM_SIGS; i++) {
		if(sig[i].free) {
			sig[i].free = FALSE;
			sig[i].count = COUNT;
			return i;
		}
	}
	if(next_preempt == NUM_SIGS)
		next_preempt = 0;
	i = next_preempt;
	sig[i].free = FALSE;
	sig[i].count = COUNT;
	return i;
}

/*==============================================================================
| free an allocated sig.
|=============================================================================*/

#define freesig(num) sig[num].free = TRUE;

/*==============================================================================
| check tcp
|=============================================================================*/

void
check(u8 *dg, size_t len, int tid)
{
	int i, n;
	iphdr *ip = (iphdr *) &dg[14];
	tcphdr *h = (tcphdr *) &dg[(ip->ihl << 2) + 14];
	u8 flags=*(((char *) h) + 13);
	struct configitem *c;

	if(((machdr*)dg)->type != MACTYPE_IPDG)
		return;

	if(ip->version != IP_VERSION)
		return;

	if(ip->protocol != PROTOCOL_TCP)
		return;

	for(i=0; i<req.index; i++) {

		int go = FALSE;

		c = &req.c[i];

		if(all_packets) continue;
		if(ip_packets) continue;
		if(tcp_and_udp_packets)	continue;

		for(n=0; n<NUM_SIGS; n++) {
			if(!sig[n].free	&& sig[n].saddr == ip->saddr	&& sig[n].daddr == ip->daddr
					&& sig[n].source == h->source	&& sig[n].dest == h->dest) {
				go = TRUE;
				if((sig[n].count--)==2) freesig(n);
				break;
			}
		}

		if(	(go) ||
			 /*=======================================================================
			 | flags must be correct
			 |======================================================================*/

			 (!(c->check_tcp_flags_on && 
					(flags & c->tcp_flags_on) != c->tcp_flags_on)		&&
			 !(c->check_tcp_flags_off && 
					(~flags & c->tcp_flags_off) != c->tcp_flags_off))

			) {

				if(c->action == ACTION_IGNORE)
					return;
				if(!*(c->action_done)) {
					c->actionf(dg, c, len, tid);
					if(!go) {
						n = newsig();
						if(n == -1)
							return;
						sig[n].saddr = ip->saddr; sig[n].daddr = ip->daddr;
						sig[n].source = h->source; sig[n].dest = h->dest;
					}
				}
			}
	}
}

