/*==============================================================================
| ether.h - macros relating to the ethernet device
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
==============================================================================*/

#ifndef ETHER_H
#define ETHER_H

#include <net/if.h>

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

#if defined NETL_LITTLE_ENDIAN

  #define MACTYPE_IPDG	0x0008
  #define MACTYPE_ARP	0x0608
  #define MACTYPE_RARP	0x3580

#elif defined NETL_BIG_ENDIAN

  #define MACTYPE_IPDG	0x0800
  #define MACTYPE_ARP	0x0806
  #define MACTYPE_RARP	0x8035

#else
  #error "byteorder undefined, fix global.h"
#endif

typedef struct {
  u8		dst[6], src[6];
  u16		type;			/* mac type */
} machdr;

#endif /* ETHER_H */
