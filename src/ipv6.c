/*==============================================================================
| ipv6.c
|   code by Graham THE Ollis <ollisg@netl.org>
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
|=============================================================================*/

/* 

THIS DOES NOT WORK.  DO NOT USE IT.  DON'T EVEN TRY WORKING ON IT.
IT IS CURRENTLY NOT USEFUL.

please NOTE: this is unfinished.  it is UNLIKELY that any of this
works yet

*/

#include <stdio.h>
#include <stdlib.h>

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"

/* i.e. find the UDP, TCP, ICMP or other useful header, and return NULL
   if it is one i haven't implemented yet.  the actual protocol type
   is returned through *prot. */

u8 *
find_last_hdr(u8 *ptr, int *prot)
{
	ip6hdr	*ip = (ip6hdr *) ptr;
	u8	*next = &ptr[sizeof(ip6hdr)];
	int	nexthdr = ip->nexthdr;

	while(1) {
		switch(nexthdr) {
			case IP6HDR_ICMP4 :
			case IP6HDR_ICMP :
			case IP6HDR_TCP :
			case IP6HDR_UDP :
				*prot = nexthdr;
				return next;

			/* 60 is the option header.  why it  isn't defined,
			   i know not.  it is distinct from the route header,
			   but the calculation is identical. */

			case IP6HDR_RH : case 60 :
				nexthdr = ((ip6hdr_route*)next)->nexthdr;
				next = &next[(((ip6hdr_route*)next)->hdrextlen+1)*8];
				break;

			case IP6HDR_FH :
				nexthdr = ((ip6hdr_frag*)next)->nexthdr;
				next = &next[8];
				break;

			default :
				return NULL;
		}
	}
}
