/*==============================================================================
| ether.h - macros relating to the ethernet device
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef ETHER_H
#define ETHER_H

#define COPYVER "0.92 (c) 1997 Graham THE Ollis <ollisg@ns.arizona.edu>"

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
  u8		src[6], dst[6];
  u16		type;			/* mac type */
};

#endif /* ETHER_H */
