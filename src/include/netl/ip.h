/*==============================================================================
| ip.h - macros relating IP protocol
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@netl.org>
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
==============================================================================*/

#ifndef NETL_IP_H
#define NETL_IP_H

#define IP_VERSION		4

/*==============================================================================
| these are for the protocol byte in the IP header
|
| the 16 bit protocol numbers are for extending netl to non ip networking.
==============================================================================*/

#define PROTOCOL_ICMP	0x01
#define PROTOCOL_IGNP	0x02
#define PROTOCOL_TCP	0x06
#define PROTOCOL_UDP	0x11

#define PROTOCOL_RAW	0x0100
#define PROTOCOL_IPX	0x0200
#define PROTOCOL_IP	0x0300

/*==============================================================================
| ENDIAN dependant items:
|
|   mactype codes
|     0800	IP datagram
|     0806	arp request/reply
|     8035	rarp
==============================================================================*/

#if defined NETL_LITTLE_ENDIAN

  #define LOCALHOST_IP	0x0100007f

typedef struct {
  int	fin:1,
	syn:1,
	rst:1,
	psh:1,
	ack:1,
	urg:1,
	reserved:2;
} flagbyte;

#elif defined NETL_BIG_ENDIAN

  #define LOCALHOST_IP	0x7f000001

typedef struct {
  int	reserved:2,
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
| IP 4
==============================================================================*/

typedef struct {
#if defined(NETL_LITTLE_ENDIAN)
	u8	ihl_version;
	#define IPIHL(ihlv) (ihlv & 0x0f)
	#define IPVER(ihlv) ((ihlv & 0xf0) >> 4)
#elif defined (NETL_BIG_ENDIAN)
	u8	ihl_version;
	#define IPIHL(ihlv) (ihlv & 0x0f)
	#define IPVER(ihlv) ((ihlv & 0xf0) >> 4)
#else
	#error	"Please fix byteorder"
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
| IP 6
==============================================================================*/

union ip6addr {
	u8	byte[16];	/* i used the dumb intel notation here for */
	u16	word[8];	/* lack of another idea */
	u32	xdouble[4];
	/*u64	quad[2];	*/
};

typedef struct {
#if defined(NETL_LITTLE_ENDIAN)
	bf_t	priority:4,
		version:4;
#elif defined (NETL_BIG_ENDIAN)
	bf_t	version:4,
  		priority:4;
#else
	#error	"Please fix <asm/byteorder.h>"
#endif
	u8	flow_lbl[3];
	u16	payload_len;

	u8	nexthdr;		/* possible values for nexthdr follow... */
#define IP6HDR_HBH	0		/* hop-by-hop options */
#define IP6HDR_ICMP4	PROTOCOL_ICMP	/* ICMP protocol (IPv4) */
#define IP6HDR_IGNP	PROTOCOL_IGNP	/* IGNP protocol (IPv4) */
#define IP6HDR_ICMP	2		/* ICMP protocol (IPv6) */
#define IP6HDR_GGP	3		/* Group to Group protocol (IPv6) */
#define IP6HDR_IP	4		/* IPv4 in IPv6 */
#define IP6HDR_ST	5		/* Stream */
#define IP6HDR_TCP	PROTOCOL_TCP	/* TCP */
#define IP6HDR_UDP	PROTOCOL_UDP	/* UDP */
#define IP6HDR_ISO_TP4	29		/* ?? */
#define IP6HDR_RH	43		/* routing header (IPv6) */
#define IP6HDR_FH	44		/* fragment header (IPv6) */
#define IP6HDR_IDRP	45		/* inter domain routing protocol */
#define IP6HDR_AH	51		/* authentication header */
#define IP6HDR_ESP	52		/* encrypted security protocol */
#define IP6HDR_NULL	59		/* no next header */
#define IP6HDR_ISO_IP	80		/* ISO Internet Protocol (CLNP) */
#define IP6HDR_IGRP	88		/* ??? */
#define IP6HDR_OSPF	89		/* Open Shortest Path First */

	u8	hop_limit;
	union ip6addr	saddr;
	union ip6addr	daddr;
} ip6hdr;

typedef struct {
	u8	nexthdr;
	u8	hdrextlen;	/* number of addresses */
	u8	type;	/* == 0 */
	u8	segleft;
	u32	reserved;
	union ip6addr	address[1];	/* actually may extend who knows how far... */
} ip6hdr_route;

typedef struct {
	u8	nexthdr;
	u8	reserved;
	u16	frag_off;
	u32	identification;
} ip6hdr_frag;

typedef struct {
	u8	nexthdr;
	u8	hdrextlen;
} ip6hdr_opt;

typedef struct {
	u8	type;
	u8	len;		/* number of octets */
	u8	data[1];	/* actually may extend who knows how far */
} ip6hdr_opt_sub;

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
	u16	source;		/* 0 */
	u16	dest;		/* 2 */
	u32	seq;		/* 4 */
	u32	ack_seq;	/* 8 */
#if defined(NETL_LITTLE_ENDIAN)
	bf_t	res1:4,		/* 12 */
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		res2:2;
#elif defined(NETL_BIG_ENDIAN)
	bf_t	doff:4,
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
	u16	window;		/* 14 */
	u16	check;		/* 16 */
	u16	urg_ptr;	/* 18 */
} tcphdr;
	/* total : 20bytes */

/*==============================================================================
| UDP
==============================================================================*/

typedef struct {
  u16	source;
  u16	dest;
  u16	len;
  u16	check;
} udphdr;

/*==============================================================================
| overlaping generic packet type thingie
| this is for the dgprintf function... wheeeee!
==============================================================================*/

typedef struct {
  machdr mac;
  iphdr ip;
  union {		/* as in subclass */
    tcphdr t;
    icmphdr i;
    udphdr u;
  } sub;
} genericpacket;

/*==============================================================================
| prototypes
==============================================================================*/

u8 *find_last_hdr(u8 *, int *);

#endif /* IP_H */
