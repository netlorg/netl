/*==============================================================================
| ether.h - macros relating to the ethernet device
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@ns.arizona.edu>
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
==============================================================================*/

#ifndef ETHER_H
#define ETHER_H

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <asm/byteorder.h>

#define IP_VERSION		4

/*==============================================================================
| these are for the protocol byte in the IP header
==============================================================================*/

#define PROTOCOL_ICMP	0x01
#define PROTOCOL_IGNP	0x02
#define PROTOCOL_TCP	0x06
#define PROTOCOL_UDP	0x11

/*==============================================================================
| ENDIAN dependant items:
|
|   net16 - this is to convert a 16 bit network integer to the local format
|
|   mactype codes
|     0800	IP datagram
|     0806	arp request/reply
|     8035	rarp
==============================================================================*/

#if defined __LITTLE_ENDIAN_BITFIELD

  #define net16(x)	( (((x) & 0xff00) >> 8) | \
			  (((x) & 0x00ff) << 8) )
  #define net32(x)	( (((x) & 0xff000000) >> 24) | \
			  (((x) & 0x00ff0000) >>  8) | \
			  (((x) & 0x0000ff00) <<  8) | \
			  (((x) & 0x000000ff) << 24) )
  #define native16(x) net16(x)
  #define native32(x) net32(x)

  #define MACTYPE_IPDG	0x0008
  #define MACTYPE_ARP	0x0608
  #define MACTYPE_RARP	0x3580

  #define LOCALHOST_IP	0x0100007f

struct flagbyte {
  u8	fin:1,
	syn:1,
	rst:1,
	psh:1,
	ack:1,
	urg:1,
	reserved:2;
};

#elif defined __BIG_ENDIAN_BITFIELD

  #define net16(x) (x)
  #define native16(x) net16(x)
  #define net32(x) (x)
  #define native32(x) net32(x)

  #define MACTYPE_IPDG	0x0800
  #define MACTYPE_ARP	0x0806
  #define MACTYPE_RARP	0x8035

  #define LOCALHOST_IP	0x7f000001

struct flagbyte {
  u8	reserved:2,
	urg:1,
	ack:1,
	psh:1,
	rst:1,
	syn:1,
	fin:1;
};

#else
  #error "Please fix <asm/byteorder.h>"
#endif


struct machdr {
  u8		dst[6], src[6];
  u16		type;			/* mac type */
};

#endif /* ETHER_H */
