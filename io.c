/*==============================================================================
| io.c
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
|  28 Feb 97  G. Ollis	.92 created module
|  05 Mar 97  G. Ollis	.93 added ope so that all io comunication is handled
|			in this module.  syslog.h should not be handled in
|			any other module.  dump data is an exception to this
|			rule.  maybe some day i'll move that stuff in to here.
|			replaced putchar() with a couple of putc()s
|=============================================================================*/

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "global.h"
#include "io.h"

int noBackground = FALSE;

/*==============================================================================
| log
|=============================================================================*/

void
log(char *cp,...)
{
  char buff[1024];	/* this should be enough memory */

  va_list vararg;
  if(cp && *cp) {
    va_start(vararg, cp);
    vsprintf(buff, cp, vararg);
    va_end(vararg);
  }

  if(noBackground)
    puts(buff);
  else
    syslog(LOG_INFO, buff);
}

void
err(char *cp,...)
{
  char buff[1024];	/* this should be enough memory */

  va_list vararg;
  if(cp && *cp) {
    va_start(vararg, cp);
    vsprintf(buff, cp, vararg);
    va_end(vararg);
  }

  if(noBackground) {
    fputs(prog, stderr);
    putc(':', stderr);
    fputs(buff, stderr);
    putc('\n', stderr);
  } else
    syslog(LOG_ERR, buff);
}

/*==============================================================================
| allocate memory, and die if we don't have enough.
|=============================================================================*/

void *
allocate(size_t size)
{
  void *tmp;

  if((tmp = malloc(size)) == NULL) {
    err("error: could not malloc(), die");
    exit(2);
  }

  return tmp;
}

/*==============================================================================
| open syslog if necessary
| this is a little silly at the moment, but does serve to better modularize
| netl.
|=============================================================================*/

void
ope(char *s)
{
  if(!noBackground)
    openlog(s, 0, NETL_LOG_FACILITY);
}

void
clo()
{
  if(!noBackground)
    closelog();
}
