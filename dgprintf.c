/*==============================================================================
| dgprintf
|   formated datagram print
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
|  12 oct 97  G. Ollis	created module
|=============================================================================*/

#include <stdio.h>
#include <string.h>

#include "global.h"
#include "ether.h"
#include "ip.h"

#include "io.h"

#define MAX_VAR_LEN	30
#define MAX_STR_LEN	512

#define VAR_NULL	0x00
#define VAR_DSTHW	0x01
#define VAR_SRCHW	0x02
#define VAR_DSTIP	0x03
#define VAR_SRCIP	0x04
#define VAR_UNKNOWN	0x7fff

/*==============================================================================
| it's the dgprintf function.  just like it says.
|=============================================================================*/

int
getvarname(char **format)
{
  char buffer[MAX_VAR_LEN + 1];
  char c = **format;
  int i;

  i = 0;

  if(**format == 0)
    return VAR_NULL;

  if(**format == '{') 
    (*format)++;

  while(1) {
    if((**format == 0) 						|| 
       (i == MAX_VAR_LEN)					||
       (c == '{' && **format == '}')				||
       (c != '{' && (**format == ' ' || **format == '\t'))) {
      buffer[i] = 0;

      if(!strcmp(buffer, "dsthw"))
        return VAR_DSTHW;
      else if(!strcmp(buffer, "srchw"))
        return VAR_SRCHW;
      else if(!strcmp(buffer, "srcip"))
        return VAR_SRCIP;
      else if(!strcmp(buffer, "dstip"))
        return VAR_DSTIP;
      else
        return VAR_UNKNOWN;
    }

    buffer[i++] = *((*format)++);
  }

  return VAR_NULL;
}

#define addchar(c) buffer[i++] = (c)
#define addstr(s) {strcpy(buffer + i, s); \
                   i+=strlen(s);}

void
dgprintf(char *format, genericpacket *dg)
{
  char buffer[MAX_STR_LEN];
  char tmp[MAX_STR_LEN];
  int i = 0;
  int n;

  while(i<MAX_STR_LEN && *format)
    if(*format == '$') {
      ++format;
      switch(n = getvarname(&format)) {

        case VAR_NULL : 
	  addstr("(null)"); 
	  break;

	case VAR_DSTHW :
          sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x",
			dg->mac.dst[0],
			dg->mac.dst[1],
			dg->mac.dst[2],
			dg->mac.dst[3],
			dg->mac.dst[4],
			dg->mac.dst[5]);
	  addstr(tmp);
	  break;

	case VAR_SRCHW :
          sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x",
			dg->mac.src[0],
			dg->mac.src[1],
			dg->mac.src[2],
			dg->mac.src[3],
			dg->mac.src[4],
			dg->mac.src[5]);
	  addstr(tmp);
	  break;

	case VAR_DSTIP :
	  sprintf(tmp, "%u.%u.%u.%u", 
                       ((char *) &dg->ip.daddr)[0],
                       ((char *) &dg->ip.daddr)[1],
                       ((char *) &dg->ip.daddr)[2],
                       ((char *) &dg->ip.daddr)[3]);
	  addstr(tmp);

	case VAR_SRCIP :
	  sprintf(tmp, "%u.%u.%u.%u", 
                       ((char *) &dg->ip.saddr)[0],
                       ((char *) &dg->ip.saddr)[1],
                       ((char *) &dg->ip.saddr)[2],
                       ((char *) &dg->ip.saddr)[3]);
	  addstr(tmp);

	default :
	  addstr("(unknown variable name)");
          break;

      }
    } else 
      addchar(*(format++));

  addchar(0);

  log(buffer);
}
