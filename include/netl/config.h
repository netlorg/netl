/*==============================================================================
| config.h - configeration manager for netl
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

#ifndef CONFIG_H
#define CONFIG_H

#define NETL_CONFIG		"/etc/netl.conf"
#define NETL_CONFIG_MAXREQ	100

/*==============================================================================
| this is for the bison parser
==============================================================================*/

typedef struct {
	int i;
	int h;
	char *s;
	int code;
} union_thingie;

/*==============================================================================
| values for the action field in the configitem structure
==============================================================================*/

#define ACTION_NONE		0
#define ACTION_LOG		1
#define ACTION_DUMP		2
#define ACTION_IGNORE		3
#define ACTION_DL		4
#define ACTION_OTHER		5	/* is this used?  i don't think so... */
#define ACTION_NULL		6
#define ACTION_USER		127

#define PROT_TCP		0
#define PROT_UDP		1
#define PROT_ICMP		2
#define PROT_IGNP		3
#define PROT_RAW		4
#define PROT_IP			5

#define PROT_TCP4		40
#define PROT_UDP4		41
#define PROT_ICMP4		42
#define PROT_IGNP4		43
#define PROT_IP4		45

#define PROT_TCP6		60
#define PROT_UDP6		61
#define PROT_ICMP6		62
#define PROT_IGNP6		63
#define PROT_IP6		65

#define PROT_USER		127

#define FLG_URG			0
#define FLG_ACK			1
#define FLG_PSH			2
#define FLG_RST			3
#define FLG_SYN			4
#define FLG_FIN			5
#define FLG_ALL			6

/*==============================================================================
| storage structure for each requirement line while netl is running
==============================================================================*/

struct configitem {
  /* 0x00 */
  u8		action;
  u16		protocol;

  /* check flags */
  u32		check_src_ip:1,
		check_dst_ip:1,
		check_src_ip6:1,
		check_dst_ip6:1,

		check_src_prt:1,	/* no ports for ICMP */
		check_dst_prt:1,

		check_src_ip_not:1,
		check_dst_ip_not:1,
		check_src_ip6_not:1,
		check_dst_ip6_not:1,

		check_src_prt_not:1,
		check_dst_prt_not:1,

		check_icmp_type:1,	/* icmp only */
		check_icmp_code:1,

		check_tcp_flags_on:1,	/* tcp only */
		check_tcp_flags_off:1,

		check_src_hw:1,
		check_dst_hw:1,
		check_src_hw_not:1,
		check_dst_hw_not:1;

  u32		src_ip, src_ip_mask,
		dst_ip, dst_ip_mask;

  u16		src_prt1,		/* udp and tcp only */
		src_prt2,
		dst_prt1,
		dst_prt2;
  u32		src_ip_not, src_ip_not_mask,
		dst_ip_not, dst_ip_not_mask;
  u16		src_prt_not,
		dst_prt_not;

  u8		icmp_type,		/* icmp only */
		icmp_code;

  u8		tcp_flags_on,		/* tcp only */
		tcp_flags_off;

  u8		src_hw[6],		/* hardware (mac) addresses */
		dst_hw[6],
		src_hw_not[6],
		dst_hw_not[6];

  union ip6addr	src_ip6,
		dst_ip6,
		src_ip6_not,
		dst_ip6_not;

  char		*logname;		/* what to give syslog */
  char		*format;
  void		(*actionf)(u8 *, struct configitem *, size_t);
  int		*action_done;
  action_mod	*actionmod;
  filt_mod	*filtermod;
};

/*==============================================================================
| the whole list of config items, stored as a dynamically allocated
| array, so it can be as large or small as you like without using more
| space than necessary
==============================================================================*/

struct configlist {
  struct configitem *c;
  int size;		/* physical size in memory */
  int index;		/* number of elemts with meaningful information */
};

/*==============================================================================
| prototypes
==============================================================================*/

#ifdef NO_SYSLOGD
void readconfig(char *confname);
#endif
#ifndef NO_SYSLOGD
void readconfig(char *confname, int nbg);
#endif
void preconfig(void);
void postconfig(void);
void clearconfig(void);
void printconfig(void);
void set_config_list(struct configlist *);

/*==============================================================================
| exported globals
==============================================================================*/

extern signed int listenport;

#endif /* CONFIG_H */
