/*==============================================================================
| netl
|   optimized (and debugged) by Graham THE Ollis <ollisg@netl.org>
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
|=============================================================================*/

static char	*id = "@(#)netl by graham the ollis <ollisg@netl.org>";
static void dumb(char *d) { dumb(id); }

#include "netl/version.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#ifndef NO_NETDB_H
#include <netdb.h>
#endif
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

#if BOOL_DYNAMIC_MODULES == 0
	register_symbols();
#endif

	/* netl_nmopen_pretend = 1; */

	/* setservent(TRUE);  */
	parsecmdline(argc, argv); 
	if(displayVersion) {
		fputs("netl ", stdout);
		puts(COPYVER);
	}
	handle();

	netl_config_pre();
	if(argc != 1) 
		while(--argc > 0) {
			argv++;
			if(argv[0][0] != '-') {
				if(debug_mode)
					err("configline:%s", argv[0]);
				netl_config_parseline(argv[0]);
				configfile = NULL;
			}
		}

	if(configfile != NULL)
#ifdef NO_SYSLOGD
		netl_config_readfile(configfile);
#endif
#ifndef NO_SYSLOGD
		netl_config_readfile(configfile, TRUE);
#endif
	netl_config_post();

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
		netl_generate_c(fp);
		if(fp != stdout)
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

