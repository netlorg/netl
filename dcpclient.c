/*==============================================================================
| dcpclient
|   code by Graham THE Ollis <ollisg@wwa.com>
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
|  15 jun 97  G. Ollis	translated from the perl version
|=============================================================================*/

char	*id = "@(#)dcpclient (c) 1997 graham the ollis <ollisg@wwa.com>";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netdb.h>

#include "global.h"
#include "io.h"

/*==============================================================================
| prototypes
|=============================================================================*/

/*==============================================================================
| main
|=============================================================================*/

int
main(int argc, char *argv[])
{
  char *message;
  u16 port=47;
  char *data;
  u16 length, strlength;
  pid_t pid = getpid();
  struct protoent *proto;
  int Socket_Handle;
  struct hostent *iaddr;
//  struct sockaddr *sin;

  prog = argv[0];

  if(argc < 2) {
    fprintf(stderr, "usage: %s message [port]\n", prog);
    return 2;
  }

  message = argv[1];
  if(argc > 2) {
    port = atoi(argv[2]);
  }

  strlength = strlen(message);
  length = 6 + strlength;
  data = allocate(length);
  memset(data, 0, length);
  memcpy(data, &pid, sizeof(pid_t));
  memcpy(data + 4, &strlength, sizeof(u16));
  memcpy(data + 6, message, length -6);

  proto = getprotobyname("udp");
  if(proto == NULL) {
    fprintf(stderr, "%s: could not getprotobyname(\"udp\")\n", prog);
    return 1;
  }

  Socket_Handle = socket(PF_INET, SOCK_DGRAM, proto->p_proto);
  if(Socket_Handle == -1) {
    fprintf(stderr, "%s: socket() error\n", prog);
    return 1;
  }

  iaddr = gethostbyname("localhost");
  if(iaddr == NULL) {
    herror(prog);
  }

  return 0;
}

