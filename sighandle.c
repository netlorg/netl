/*==============================================================================
| sighandle.c
|   catch some simple signals 
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
|  08 Feb 97  G. Ollis	created
|  28 Feb 97  G. Ollis	.92 output can go to stdout or syslog depending on
|			how netl is called.
|  07 Mar 97  G. Ollis	.93 added description for fatal signals in log file
|  09 Mar 97  G. Ollis	added a call to void cleanup() function which should
|			be defined elsewhere, probably the same module as the
|			main function.
|=============================================================================*/

#include <signal.h>
#include <stdio.h>

#include "netl/global.h"

#include "netl/sighandle.h"
#include "netl/io.h"

/*==============================================================================
| handle();
| install the signal handler.
==============================================================================*/

void
handle()
{
	void	(*old_handler)();

	old_handler = signal(SIGTERM, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGTERM handler TERM");

	old_handler = signal(SIGQUIT, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGQUIT handler TERM");

	old_handler = signal(SIGHUP, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGHUP handler TERM");

	old_handler = signal(SIGINT, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGINT handler TERM");

	old_handler = signal(SIGSEGV, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGSEGV handler TERM");

	log("signal handler installed");
}

/*==============================================================================
| handle();
| install the signal handler.
==============================================================================*/

extern int line;	/* hack, formerly static variable in config.c */
void cleanup();		/* somewhere else, not quite as much of a hack */

void
sig_handler(int sig)
{
	switch(sig) {
		case SIGTERM : log("termination signal"); break;
		case SIGTRAP : log("trace/breakpoint trap"); break;
		case SIGQUIT : log("keyboard quit"); break;
		case SIGHUP  : log("hangup detected"); break;
		case SIGINT  : log("interupt from keyboard"); break;

		case SIGSEGV : 
				log("invalid memory refrence");
			break;

		default: break;
	}
	err("caught signal %d, die", sig);
	cleanup();
	exit(1);
}

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

