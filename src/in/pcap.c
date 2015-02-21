/*==============================================================================
| pcap.c
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
|=============================================================================*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pcap.h>

#include "netl/global.h"

#include "netl/io.h"

/*==============================================================================
| prepare the ethernet card.  this usually involves putting the card in to
| promiscuious mode.
|=============================================================================*/

static char error[PCAP_ERRBUF_SIZE];
static pcap_t *pc;

fun_prefix int offset;

fun_prefix char *
prepare(char *dev)
{
	pc = pcap_open_live(	dev,		/* char *device */
				4096,		/* int snaplen */
				TRUE,		/* int promisc */
				20,		/* int to_ms */
				error);		/* char *ebuf */
	if(pc == NULL) {
		fprintf(stderr, "libpcal error %s\n", error);
		exit(1);
	}

	offset = 14;

/*	switch(pcap_datalink(pc)) {
		case DTL_EN10MB : offset = 14; break;
		case DTL_IEEE802 : offset =  22; break;
		case DTL_NULL: offset = 22; break;
		case DTL_SLIP : case DTL_PPP : offset = 24; break;
		case DTL_RAW : offset = 0; break;
		default :
			fprintf(stderr, "pcap error: Unknown datalink type");
			exit(1);
	}*/

	return dev;
}

/*==============================================================================
| grab - grab the next packet that happens to pass by.
| return the size of the packet, returns -1 on error
|=============================================================================*/

fun_prefix unsigned char *
grab(int *len)
{
	struct pcap_pkthdr h;
	const u_char *p;
	while((p = pcap_next(pc, &h)) == NULL)
		;
	if(h.caplen != h.len)
		err("libpcap usage warning: caplen = %d, len = %d", h.caplen, h.len);
	*len = h.caplen;
	return (unsigned char *) p;
}

#if BOOL_DYNAMIC_MODULES == 0
void    
in_pcap_register_symbols(void)
{
	register_symbol("in/pcap.so", "prepare", prepare);
	register_symbol("in/pcap.so", "grab", grab);
	register_symbol("in/pcap.so", "offset", offset);
}       
#endif  
        

