/*==============================================================================
| config.h - configeration manager for netl
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

#ifndef CONFIG_H
#define CONFIG_H

#define NETL_CONFIG		"/etc/netl.conf"
#define NETL_CONFIG_MAXWIDTH	255
#define NETL_CONFIG_MAXTOKENS	20
#define NETL_CONFIG_MAXREQ	100

/*==============================================================================
| values for the action field in the configitem structure
==============================================================================*/

#define ACTION_NONE		0
#define ACTION_LOG		1
#define ACTION_DUMP		2
#define ACTION_IGNORE		3

/*==============================================================================
| storage structure for each requirement line while netl is running
==============================================================================*/

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
void preconfig();
void postconfig();
void clearconfig();

/*==============================================================================
| exported globals
==============================================================================*/

extern int configmax;
extern struct configlist icmp_req, tcp_req, udp_req;
extern signed int listenport;

#endif /* CONFIG_H */
