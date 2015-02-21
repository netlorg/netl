/*==============================================================================
| api.h - API for the outside world
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

#ifndef NETL_API_H
#define NETL_API_H

/* sorry, but i need theses ... */
#include <sys/types.h>
#include <stdio.h>

/* FIXME: size_t and FILE need to be defined */

/* GUTS */
extern int netl_guts_yy_line_number;

/* CONFIG */
void netl_config_readfile(char *, int);
void netl_config_parseline(char *);
void netl_config_pre(void);
void netl_config_post(void);
void netl_config_set(void *);	/* this is probably guts material, but oh well */
void netl_config_clear(void);

/* CATCH */
void netl_catch_prepare(int);
int netl_catch_fork(char *, char **);
typedef struct { char *name; char *packet; int packet_len; } netl_catch_t;
netl_catch_t *netl_catch_catch(void);

/* PACKET */
void netl_packet_check(char *, size_t);

/* GENERATE */
void netl_generate_c(FILE *fp);

/* NETL : !! FIXME !! document !! */
int netl(char *dev);

/* IO : !! FIXME !! document !! */
void netl_io_die(int retval, char *cp, ...);
unsigned char *netl_io_readfile(char *fn, size_t *size, size_t max, char *prog);
void netl_io_dumpf(unsigned char *data, size_t size, FILE *fd);
void netl_io_log(char *cp, ...);
void netl_io_err(char *cp, ...);
void netl_io_ope(char *s);
void netl_io_clo();
int netl_io_ahextoi(char *s);
void *netl_io_allocate(size_t size);

/* RESOLVE : !! FIXME !! document !! */
typedef unsigned int u32; /* usually the case */
extern int netl_config_resolveHostnames;
char *netl_resolve_addip(const char *s, u32 ip);
char *netl_resolve_ip2string(u32 ip);
char *netl_resolve_search(u32 ip);
u32 netl_resolve_searchbyname(char *name);
void netl_resolve_clear(void);

/* TABLE : !! FIXME !! document !! */
#define MAXICMPTYPE 13
#define MAXICMP6TYPE 17
#define MAXICMPCODE 22
struct lookupitem {
	int index;
	char *name;
};
extern struct lookupitem
	netl_table_icmptype[MAXICMPTYPE],
	netl_table_icmp6type[MAXICMP6TYPE],
	netl_table_icmpcode[MAXICMPCODE];

/* NM : !! FIXME !! reimplement !! */

#endif
