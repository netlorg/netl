/*==============================================================================
| netl
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
|  01 Feb 97  G. Ollis	modified, commented (and debugged)
|  08 Feb 97  G. Ollis	added IP address resolving.
|  23 Feb 97  G. Ollis	combined all network monitoring in to single program
|  28 Feb 97  G. Ollis	.92 added the -z option [ and the log() function to
|			replace syslog()]
|  05 Mar 97  G. Ollis	.93 added run time comunication.
|			took all direct syslog stuff out of this module.
|  07 Mar 97  G. Ollis	changed dump name to /tmp/netl/name-pid-time.dg.
|  26 sep 97  G. Ollis	took the networking specific portion of the code out
|			of this module and put it in to grab.c.
|=============================================================================*/

char	*id = "@(#)netl by graham the ollis <ollisg@ns.arizona.edu>";

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#ifdef OS_WIN32
  #include <winsock.h>
#endif

#include "global.h"
#include "ether.h"
#include "ip.h"

#include "netl.h"
#include "sighandle.h"
#include "io.h"
#include "options.h"
#include "config.h"
#include "resolve.h"
#include "dcp.h"
#include "grab.h"
#include "parse.h"

/*==============================================================================
| Globals
|=============================================================================*/

char *prog;
u8 localhardware[6] = {0, 0, 0, 0, 0, 0};
u8 localip[4] = {127, 0, 0, 1};

/*==============================================================================
| it's the clean up function!  it really doesn't need to do much so...
| (btw- clo is the name of the planet the decepticons invaded shortly after 
| the battle with unicron.  the autobots initially sustained incredable 
| losses, optimus prime returns and turns the tide with the help of the 
| "last autobot".  however, this has nothing to do with the clean up function)
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
    fputs("netl ", stdout);
    puts(COPYVER);
  }

  preconfig();
  if(argc != 1) 
    while(--argc > 0) {
      argv++;
      if(argv[0][0] != '-') {
        parseconfigline(argv[0]);
        configfile = NULL;
      }
    }

  if(configfile != NULL)
#ifdef NO_SYSLOGD
    readconfig(configfile);
#endif
#ifndef NO_SYSLOGD
    readconfig(configfile, TRUE);
#endif
  postconfig();

  if(debug_mode) {
    printconfig();
    return 1;
  }

  if(getuid() != 0) {
    fprintf(stderr, "%s: must be run as root\n", prog);
    return 1;
  }

#ifndef NO_SYSLOGD
  if(noBackground)
#endif
    return netl(netdevice);
#ifndef NO_SYSLOGD
  else {
    if((temp = fork()) == 0) 
      return netl(netdevice);

    if(temp == -1) {
      fprintf(stderr, "%s: unable to fork\n", prog);
      return 1;
    }
  }
#endif

  return 0;
}

/*==============================================================================
| void netl(char *)
|=============================================================================*/

int
netl(char *dev)
{
  int		l;
  unsigned char buf[4096];

  ope("netl");
  log("starting netl, logging %s", dev);
  handle();

  prepare(dev);

  /*============================================================================
  | Entering the data collection loop
  |===========================================================================*/

  while(47) {
    if((l = grab(buf)) < 0) {
      log(strerror(errno));
      err("Error receiving RAW packet");
    } else 
      parsedg(buf, l);
  }

  return 0;
}

