/*==============================================================================
| lookup.h - lookup tables for ICMP TYPEs and CODEs
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@wwa.com>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@wwa.com>
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
|  05 Mar 97  G. Ollis	.93 stole the ICMP #defines from the linux kernel
|			2.0.11 header files are missing a few of the ICMP
|			codes.
==============================================================================*/

#ifndef LOOKUP_H
#define LOOKUP_H

struct lookupitem {
  int	index;
  char	*name;
};

#define MAXICMPTYPE		13
#define MAXICMP6TYPE		17
#define MAXICMPCODE		22

extern struct lookupitem icmptype[MAXICMPTYPE];
extern struct lookupitem icmp6type[MAXICMP6TYPE];
extern struct lookupitem icmpcode[MAXICMPCODE];

/*==============================================================================
| these defines were copied right out of the kernel header file
| icmp.h, for those of you with older kernels.
| if all these things are defined in your kernel header file then this is
| pretty silly, but oh well.
==============================================================================*/

/*==============================================================================
| for the type field in the icmp header
==============================================================================*/

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/

#define ICMP6_DEST_UNREACH	1	/* destination unreachable	*/
#define ICMP6_PACKET_TOO_BIG	2	/* packet too big		*/
#define ICMP6_TIME_EXCEEDED	3	/* time exceeded		*/
#define ICMP6_PARAMETER_PROB	4	/* parameter problem		*/
#define ICMP6_ECHO_REQUEST	128
#define ICMP6_ECHO_REPLY	129
#define ICMP6_GMQUERY		130	/* group meembership query	*/
#define ICMP6_GMREPORT		131
#define ICMP6_GMREDUCTION	132
#define ICMP6_ROUTER_SOLICITATION 133
#define ICMP6_ROUTER_ADVERTISEMENT 134
#define ICMP6_NEIGHBOR_SOLICITATION 135
#define ICMP6_NETGHBOR_ADVERTISEMENT 136
#define ICMP6_REDIRECT		137

/*==============================================================================
| Codes for UNREACH.
==============================================================================*/

#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */

/*==============================================================================
| Codes for REDIRECT.
==============================================================================*/

#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/*==============================================================================
| Codes for TIME_EXCEEDED.
==============================================================================*/

#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

#endif /* LOOKUP_H */
