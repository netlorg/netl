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
| GLOBALS
|=============================================================================*/

int (*grab)(char *buf);

// grab globals
char *in_path = "in";
void *grab_module = NULL;
int (*grab)(char *);

/*==============================================================================
| prepare dl wrapper
|=============================================================================*/

void
prepare(char *dev)
{
	char str_buffer[1024];
	void (*prepare_function)(char *);

	if(grab_module != NULL) {
		nmclose(grab_module);
	}
	snprintf(str_buffer, 1024, "%s/%s/%s.so", so_path, in_path, grab_module_name);
	grab_module = nmopen(str_buffer);

	prepare_function = nmsym(grab_module, "prepare");

	prepare_function(dev);

	grab = nmsym(grab_module, "grab");
}

/*==============================================================================
| void netl(char *)
|=============================================================================*/

int reload_config_file = 0;

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

	while(47) {			/* valnumdez's NoOp */
		if((l = grab(buf)) < 0) {
			log(strerror(errno));
			err("Error receiving RAW packet");
		} else {
			check(buf, l);
		}

		if(reload_config_file) {
			reload_config_file = 0;

			clearipcache();
			log("old ip cache cleared");

			clearconfig();

			preconfig();
			#ifdef NO_SYSLOGD
				readconfig(configfile);
			#else
				readconfig(configfile, noBackground);
			#endif
			postconfig();
			log("re-read configfile %s", configfile);
		}
	}

	return 0;
}
