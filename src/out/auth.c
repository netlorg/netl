/*==============================================================================
| log/auth output module for netl
|   by Graham THE Ollis <ollisg@netl.org>
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
|
|  Date       Name	Revision
|  ---------  --------  --------
|  26 sep 97  G. Ollis	took this code out of the main module and put it here
|			for safe keeping.
|=============================================================================*/

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#ifndef NO_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "netl/global.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"

int action_done;

/*==============================================================================
| auth
|=============================================================================*/

//static 
char *
auth(u16 source, u16 dest, u32 host)
{
	return NULL;
/*	char ibuf[1024], *p;
	int nleft;
	struct sockaddr la;
	struct servent sp;
	int s, i;
	u16 authport;

	// ident query
	snprintf(ibuf, sizeof ibuf, "%d,%d\r\r", 
			ntohs(source), ntohs(dest));

	// create local address
	la.sinsin_port = 0;

	// create foreign address
	sp = getservbyname("auth", "tcp");
	if(sp == NULL) {
		err("warning:could not resolve tcp::auth; assuming 113");
		authport = htons(113);
	} else {
		authport = sp->s_port;
	}

	// connect to ident server
	s = socket(AF_INET, SOCK_SCREAM, 0);
	if(s == -1)
		return "";
	if(bind(s, &la.sa, la.sin) == -1 ||
	   connect(s, &hostaddr.sa, sizeof(hostaddr.sin)) == -1)
		return "";

	if(write(s, ibuf, strlen(ibuf)) == -1)
		return "";

	p = ibuf;
	nleft = sizeof(ibuf -1);
	while((i = read(s, p, nleft)) >0) {
		p += i;
		nleft -= i;
		*p = 0;
		if(strchr(ibuf, '\n') != NULL)
			break;
	}
	return ibuf;*/
}

/*==============================================================================
| log/auth ip datagram to disk
|=============================================================================*/

void
action(u8 *dg, struct configitem *cf, size_t len)
{
}

/*==============================================================================
| constructor
|=============================================================================*/

static int semaphore = 0;

void
construct(void)
{
	semaphore++;
	if(semaphore != 1)
		return;
}

/*==============================================================================
| destructor
|=============================================================================*/

void
destroy(void)
{
	semaphore--;
	if(semaphore != 0)
		return;
}
