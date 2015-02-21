/*==============================================================================
| grab.c
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
|  26 sep 97  G. Ollis	took this code out of the main module.  this is all 
|			linux specific so far (ahh... there is a reason
|			go figure.)  all the networking code goes here.
|=============================================================================*/

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

#include "netl/global.h"
#include "netl/io.h"
#include "netl/ether.h"
#include "netl/grab.h"

/*==============================================================================
| remember the power of three: linux, perl and dr. pepper.
|=============================================================================*/

/*==============================================================================
| prepare the ethernet card.  this usually involves putting the card in to
| promiscuious mode.
|=============================================================================*/

static int sock;
static struct sockaddr_in name;
static unsigned int fromlen;

void
prepare(char *dev)
{
	int length; 
	struct ifreq oldifr, ifr;

	/*============================================================================
	| Get a socket which will collect all packets
	|===========================================================================*/

	if((sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
		err(strerror(errno));
		die(1, "cannot open raw socket");
	}

	/*============================================================================
	| Configure ethernet device
	|===========================================================================*/

	strcpy(ifr.ifr_name, dev);

	/*============================================================================
	| Get flags and place them in ifr structure
	|===========================================================================*/

	if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		die(1, "unable to get %s flags, die", dev);
	}

	memcpy(&oldifr, &ifr, sizeof(struct ifreq));

	/*============================================================================
	| Set the promiscous flag
	|===========================================================================*/

	ifr.ifr_flags |= IFF_PROMISC;

	/*============================================================================
	| Set the device flags
	|===========================================================================*/

	if(ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		die(1, "Unable to set %s flags, die", dev);
	} 

	/*============================================================================
	| Set up sockaddr
	|===========================================================================*/

	name.sin_family = AF_INET;
	name.sin_addr.s_addr = INADDR_ANY;
	name.sin_port = 0;

	length = sizeof(name);

	if(getsockname(sock, (struct sockaddr *) &name, &length) < 0) {
		die(1, "Error: Can't get socket name, die");
	}
}

/*==============================================================================
| grab - grab the next packet that happens to pass by.
| return the size of the packet, returns -1 on error
|=============================================================================*/

int
grab(char *buf)
{
	return recvfrom(sock, buf, 1024, 0, (struct sockaddr *) &name, &fromlen);
}

