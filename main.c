/*==============================================================================
| netl
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
|  26 sep 97  G. Ollis	took the networking specific portion of the code out
|			of this module and put it in to grab.c.
|=============================================================================*/

static char	*id = "@(#)netl by graham the ollis <ollisg@wwa.com>";
static void dumb(char *d) { dumb(id); }

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"

#include "netl/netl.h"
#include "netl/sighandle.h"
#include "netl/io.h"
#include "netl/options.h"
#include "netl/filter.h"
#include "netl/action.h"
#include "netl/config.h"
#include "netl/resolve.h"
#include "netl/grab.h"
#include "netl/check.h"
#include "netl/compiler.h"

/*==============================================================================
| int main()
|  + from here, we call functions in options.c to parse the command line.
|    from there, we decide where, if any a config file needs to be read using
|    the parser, scanner in config.l and config.y.  lastly, we fork a process
|    running the function netl().  if it's windows, or if the user requests not
|    to run in the background, then it won't fork of course.
|=============================================================================*/

int
main(int argc, char *argv[])
{
#ifndef NO_SYSLOGD
	pid_t		temp;
#endif
	prog = argv[0];

	//setservent(TRUE);
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
				if(debug_mode)
					err("configline:%s", argv[0]);
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
		//printconfig();
		//return 1;
	}

	if(output_mode == OUT_MODE_C) {
		FILE *fp;
		if(output_name[0] == '-' && output_name[1] == 0)
			fp = stdout;
		else
			fp = fopen(output_name, "w");
		if(fp == NULL) {
			fprintf(stderr, "%s: error opening %s for write!\n",
				prog, output_name);
		}
		generate_c(fp);
		fclose(fp);
		return 0;
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

