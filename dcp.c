/*==============================================================================
| dcp.c - discrete comunication protocol
|   optimized (and debugged) by Graham THE Ollis <ollisg@ns.arizona.edu>
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
|
|  Date       Name	Revision
|  ---------  --------  --------
|  09 Mar 97  G. Ollis	created module
|=============================================================================*/

#include <string.h>
#include <stdio.h>

#include "global.h"
#include "ether.h"
#include "ip.h"

#include "io.h"
#include "config.h"
#include "dcp.h"
#include "options.h"
#include "resolve.h"

/*==============================================================================
| globals
|=============================================================================*/

u32 lasthearid = 0;

/*==============================================================================
| process a comunication request
|=============================================================================*/

void
hear(u8 *dg, udphdr *h, int len)
{
  char		message[MAX_COM_LEN];
  int		size, offset;
  u32		id;
  u16		nsize;

  /*============================================================================
  | convert the udp packet in to a c string.
  | that's c string as in STANDARD ANSI C character array type STRING thing.
  | not "i'm a sorry ass microsoft lacky who's going to spend the rest of his
  | life playing silly games while graham takes over the world" c strings.
  |===========================================================================*/

  offset = sizeof(machdr) + sizeof(iphdr) + sizeof(udphdr);

  id = ntohl(*((u32 *) &dg[offset]));		offset += 4;
  if(id == lasthearid)
    return;
  lasthearid = id;
  nsize = ntohs(*((u16 *) &dg[offset]));	offset += 2;

  size = len - offset;
  if(nsize < size)
    size = nsize;

  if(size > MAX_COM_LEN - 1)
    size = MAX_COM_LEN - 1;
  memcpy(message, &dg[offset], size);
  message[size] = '\0';

  /*============================================================================
  | all comunication requests are logged, even if we ignore them
  |===========================================================================*/

  log("nets[%d]: \"%s\"", id, message);

  if(!strncmp("netl:", message, 5)) {
    if(!strncmp("readconfig", &message[5], 10)) {

      clearipcache();
      log("old ip cache cleared");
     
      clearconfig();
      log("old configuration cleared");

      preconfig();
#ifdef NO_SYSLOGD
      readconfig(configfile);
#else
      readconfig(configfile, noBackground);
#endif
      postconfig();
      log("re-read configfile %s", configfile);

    } else 
      err("warning: unknown netl comunication request %s", &message[5]);
  }
}

