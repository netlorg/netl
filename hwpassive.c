/*==============================================================================
| hwpassive
|   optimized (and debugged) by Graham THE Ollis <ollisg@wwa.com>
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
|  01 Feb 97  G. Ollis	modified, commented (and debugged)
|  08 Feb 97  G. Ollis	added IP address resolving.
|  23 Feb 97  G. Ollis	combined all network monitoring in to single program
|  28 Feb 97  G. Ollis	.92 added the -z option [ and the log() function to
|			replace syslog()]
|  05 Mar 97  G. Ollis	.93 added run time comunication.
|			took all direct syslog stuff out of this module.
|  07 Mar 97  G. Ollis	changed dump name to /tmp/netl/name-pid-time.dg.
|  09 Mar 97  G. Ollis	converted to hwpassive.c from netl.c
|=============================================================================*/

char	*id = "@(#)hwpassive by graham the ollis <ollisg@wwa.com>";

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <netdb.h>

#include "global.h"
#include "ether.h"
#include "ip.h"

#include "io.h"
#include "options.h"
#include "config.h"
#include "sighandle.h"

/*==============================================================================
| data structures
|=============================================================================*/

typedef struct st {
  u8			hw[6];
  u32			ip;
  struct st		*next;
} stack_t;

/*==============================================================================
| Globals
|=============================================================================*/

int		hwpassive(char *dev);
int		line=0;				/* yet another hack *sigh*/
void		parsedg(u8 *dg, int len);

struct ifreq	oldifr, ifr;
stack_t		*head=NULL;
u8		hwignore1[6] = { 0xff, 0xff, 0xff,
				 0xff, 0xff, 0xff};
u8		hwignore2[6] = { 0x00, 0x00, 0x00,
				 0x00, 0x00, 0x00};

/*==============================================================================
| it's the clean up function!  it really doesn't need to do much so...
|=============================================================================*/

void cleanup()
{
  clo();
}

/*==============================================================================
| int main(int, char **)
|=============================================================================*/

int
main(int argc, char *argv[])
{
#ifndef NO_SYSLOGD
  pid_t		temp;
#endif

  prog = argv[0];

  setservent(TRUE);
  parsecmdline(argc, argv); 
  if(displayVersion) {
    fputs("hwpassive ", stdout);
    puts(COPYVER);
  }

  if(getuid() != 0) {
    fprintf(stderr, "%s: must be run as root\n", argv[0]);
    return 1;
  }

  if(argc != 1) 
    while(--argc > 0) {
      argv++;
      if(argv[0][0] != '-') {
         /* NULL */
      }
    }

#ifndef NO_SYSLOGD
  if(noBackground)
#endif
    return hwpassive(netdevice);
#ifndef NO_SYSLOGD
  else {
    if((temp = fork()) == 0) 
      return hwpassive(netdevice);

    if(temp == -1) {
      fprintf(stderr, "%s: unable to fork\n", argv[0]);
      return 1;
    }
  }
#endif

  return 0;
}

/*==============================================================================
| void hwpassive(char *)
|=============================================================================*/

int
hwpassive(char *dev) {
  int		l;
  int		sock, length;
  struct	sockaddr_in name;
  unsigned char buf[4096];
  unsigned int	fromlen;

  ope("hwpassive");
  log("starting hwpassive, logging %s", dev);
  handle();

  /*============================================================================
  | Get a socket which will collect all packets
  |===========================================================================*/

  if((sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
    err("cannot open raw socket, die");
    return 1;
  }

  /*============================================================================
  | Configure ethernet device
  |===========================================================================*/

  strcpy(ifr.ifr_name, dev);
  strcpy(oldifr.ifr_name, dev);

  /*============================================================================
  | Get flags and place them in ifr structure
  |===========================================================================*/

  if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
    err("unable to get %s flags, die", dev);
    return 1;
  }

  /*============================================================================
  | Get flags and place them in oldifr structure
  | This will be used later to change ether device characteristics back
  | to their original value
  |===========================================================================*/

  if(ioctl(sock, SIOCGIFFLAGS, &oldifr) < 0) {
    err("unable to get %s flags, die", dev);
    return 1;
  }

  /*============================================================================
  | Set the promiscous flag
  |===========================================================================*/

  ifr.ifr_flags |= IFF_PROMISC;

  /*============================================================================
  | Set the device flags
  |===========================================================================*/

  if(ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
    err("Unable to set %s flags, die", dev);
    return 1;
  } 

  /*============================================================================
  | Set up sockaddr
  |===========================================================================*/

  name.sin_family = AF_INET;
  name.sin_addr.s_addr = INADDR_ANY;
  name.sin_port = 0;

  length = sizeof(name);

  if(getsockname(sock, (struct sockaddr *) &name, &length) < 0) {
    err("Error: Can't get socket name, die");
    return 1;
  }

  /*============================================================================
  | Entering the data collection loop
  |===========================================================================*/

  for(;;) {
    if((l = recvfrom(sock, buf, 1024, 0, 
		     (struct sockaddr *) &name, &fromlen)) < 0)
      err("Error receiving RAW packet");
    else 
      parsedg(buf, l);
  }

  return 0;
}

/*==============================================================================
| add an entry if it's not already there to the list
|=============================================================================*/

void
addent(u8 *hw, u32 ip)
{
  stack_t		*tmp;
  u8			*ptr;

  ptr = (u8 *) &ip;

  if(!memcmp(hwignore1, hw, 6) || !memcmp(hwignore2, hw, 6))
    return;

  if(ptr[0] != 150 || ptr[1] != 135 ||
     ptr[2] == 255 || ptr[3] == 255)
    return;

  /*============================================================================
  | traverse the stack and see if we have the ip/hw on the list
  |===========================================================================*/

  for(tmp=head; tmp!=NULL; tmp=tmp->next)
    if(!memcmp(hw, tmp->hw, 6) && tmp->ip == ip)
      return;

  /*============================================================================
  | it wasn't in the list, so add it to the top.
  |===========================================================================*/

/*  log("add %02x.%02x.%02x.%02x.%02x.%02x <=> %d.%d.%d.%d",
      hw[0], hw[1], hw[2], hw[3], hw[4], hw[5], 
      ptr[0], ptr[1], ptr[2], ptr[3]);*/

  tmp = (stack_t *) allocate(sizeof(stack_t));
  tmp->ip = ip;
  memcpy(tmp->hw, hw, 6);
  tmp->next = head;
  head = tmp;
}

/*==============================================================================
| void parsedg(u8 *buff);
|=============================================================================*/

void
parsedg(u8 *dg, int len)
{
  machdr	*mac = (machdr*) dg;
  iphdr		*ip = (iphdr*) &dg[14];

  /*============================================================================
  | check that this is a ip datagram.
  | check the version number.  should be ip version 4.
  |===========================================================================*/

  if(mac->type != MACTYPE_IPDG || ip->version != IP_VERSION) 
    return;

  addent(mac->src, ip->saddr);
  addent(mac->dst, ip->daddr);
}

