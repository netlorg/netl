/*==============================================================================
| ipx.h - macros relating IPX/SPX protocol
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

#ifndef NETL_IPX_H
#define NETL_IPX_H

#define IPX_NODE_LENGTH	6
#define IPX_MTU		576

typedef struct {
	u32	net;
	u8	node[IPX_NODE_LENGTH];
	u16	sock;
} ipxaddress;

typedef struct {
	u16	checksup;
	u16	pktsize;
	u8 	tctrl;
	u8	type;

#define IPX_TYPE_UNKNOWN	0x00
#define IPX_TYPE_RIP		0x01	// may also be 0
#define IPX_TYPE_SAP		0x04	// may also be 0
#define IPX_TYPE_SPX		0x05	// SPX protocol
#define IPX_TYPE_NCP		0x11	// $lots for docs on this (SPLIT)
#define IPX_TYPE_PPROP		0x14	// complicated flood fill brdcast
	ipxaddress ipx_dest;
	ipxaddress ipx_source;
} ipxhdr;

typedef struct {
	ipxhdr	ipx;
	u8	cctl;
	u8	dtype;
#define SPX_DTYPE_ECONN		0xfe
#define SPX_DTYPE_ECACK		0xff
	u16	sconn;
	u16	dconn;
	u16	sequence;
	u16	ackseq;
	u16	allocseq;
} spxhdr;

#endif /* IP_H */
