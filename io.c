/*==============================================================================
| io.c
|   optimized (and debugged) by Graham THE Ollis <ollisg@ns.arizona.edu>
|
| this code is (c) 1997 Graham THE Ollis
|
|  io module for deamon class programs.
|  your free to modify and distribute this program as long as this header is
|  retained, source code is made *freely* available and you document your 
|  changes in some readable manner.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  28 Feb 97  G. Ollis	.92 created module
|=============================================================================*/

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
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
    fputs(buff, stderr);
    putchar('\n');
  } else
    syslog(LOG_ERR, buff);
}

