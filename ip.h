/*==============================================================================
| ip.h - macros relating IP protocol
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

#ifndef IP_H
#define IP_H

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
|   mactype codes
|     0800	IP datagram
|     0806	arp request/reply
|     8035	rarp
==============================================================================*/

#if defined LITTLE_ENDIAN

  #define LOCALHOST_IP	0x0100007f

typedef struct {
  u8	fin:1,
	syn:1,
	rst:1,
	psh:1,
	ack:1,
	urg:1,
	reserved:2;
} flagbyte;

#elif defined BIG_ENDIAN

  #define LOCALHOST_IP	0x7f000001

typedef struct {
  u8	reserved:2,
	urg:1,
	ack:1,
	psh:1,
	rst:1,
	syn:1,
	fin:1;
} flagbyte;

#else
  #error "byte order undefined, please fix global.h"
#endif

/*==============================================================================
| IP
==============================================================================*/

typedef struct {
#if defined(LITTLE_ENDIAN)
	u8	ihl:4,
		version:4;
#elif defined (BIG_ENDIAN)
	u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	u8	tos;
	u16	tot_len;
	u16	id;
	u16	frag_off;
	u8	ttl;
	u8	protocol;
	u16	check;
	u32	saddr;
	u32	daddr;
	/*The options start here. */
} iphdr;

/*==============================================================================
| ICMP
==============================================================================*/

typedef struct {
  u8		type;
  u8		code;
  u16		checksum;
  union {
	struct {
		u16	id;
		u16	sequence;
	} echo;
	u32	gateway;
  } un;
} icmphdr;

/*==============================================================================
| TCP
==============================================================================*/

typedef struct {
	u16	source;
	u16	dest;
	u32	seq;
	u32	ack_seq;
#if defined(LITTLE_ENDIAN)
	u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		res2:2;
#elif defined(BIG_ENDIAN)
	u16	doff:4,
		res1:4,
		res2:2,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	u16	window;
	u16	check;
	u16	urg_ptr;
} tcphdr;

/*==============================================================================
| UDP
==============================================================================*/

typedef struct {
  u16	source;
  u16	dest;
  u16	len;
  u16	check;
} udphdr;

#endif /* IP_H */
