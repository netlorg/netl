/*==============================================================================
| netl - log EVERYTHING possible
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef linux
  #error netl requires linux
#endif

#ifndef NETL_H
#define NETL_H

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <asm/byteorder.h>

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;

#define NETL_LOG_FACILITY	LOG_LOCAL4
#define NETL_CONFIG		"/etc/netl.conf"
#define NETL_CONFIG_MAXWIDTH	255
#define NETL_CONFIG_MAXTOKENS	20
#define NETL_CONFIG_MAXREQ	100
#define IP_VERSION		4

#define ACTION_NONE		0
#define ACTION_LOG		1
#define ACTION_DUMP		2
#define ACTION_IGNORE		3

#define TRUE			1
#define FALSE			0



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

  #define net16(x) (((x) & 0xff00) >> 8) | \
                   (((x) & 0x00ff) << 8)
  #define native16(x) net16(x)

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

struct configitem {
  /* 0x00 */
  u8		action;
  u8		protocol;

  /* check flags */
  u16		check_src_ip:1,
		check_dst_ip:1,

		check_src_prt:1,	/* no ports for ICMP */
		check_dst_prt:1,

		check_src_ip_not:1,
		check_dst_ip_not:1,

		check_src_prt_not:1,
		check_dst_prt_not:1,

		check_icmp_type:1,	/* icmp only */
		check_icmp_code:1,

		check_tcp_flags_on:1,	/* tcp only */
		check_tcp_flags_off:1;

  u32		src_ip,
		dst_ip;
  u16		src_prt1,		/* udp and tcp only */
		src_prt2,
		dst_prt1,
		dst_prt2;
  u32		src_ip_not,
		dst_ip_not;
  u16		src_prt_not,
		dst_prt_not;

  u8		icmp_type,		/* icmp only */
		icmp_code;

  u8		tcp_flags_on,		/* tcp only */
		tcp_flags_off;

  char		*logname;		/* what to give syslog */
};

struct configlist {
  struct configitem *c;
  int size;		/* physical size in memory */
  int index;		/* number of elemts with meaningful information */
};

/*==============================================================================
| resolve.c - the ip resolution module
==============================================================================*/

char	*addip(const char *s, u32 ip);
char	*ip2string(u32 ip);
char	*search(u32 ip);
u32	searchbyname(char *);
void	clearipcache();

/*==============================================================================
| sighandle.c - the signal handling module
==============================================================================*/

void	handle();
void	sig_handler(int sig);

/*==============================================================================
| netl.c - main functions
==============================================================================*/

int	netl(char *dev);
void	parsedg(u8 *dg, int len);

/*==============================================================================
| config.c - manage the netl configeration file
==============================================================================*/

void readconfig(char *programname, char *confname);

extern int configmax;
extern struct configlist icmp_req, tcp_req, udp_req;
extern char netdevice[255];

#endif /* NETL_H */
