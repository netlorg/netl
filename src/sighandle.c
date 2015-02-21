/*==============================================================================
| sighandle.c
|   catch some simple signals 
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
	static void sig_handler(int sig);
	void	(*old_handler)();

	old_handler = signal(SIGTERM, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGTERM handler TERM");

#ifdef SIGQUIT
	old_handler = signal(SIGQUIT, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGQUIT handler TERM");
#endif

#ifdef SIGHUP
	old_handler = signal(SIGHUP, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGHUP handler TERM");
#endif

	old_handler = signal(SIGINT, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGINT handler TERM");

	old_handler = signal(SIGSEGV, &sig_handler);
	if(old_handler == SIG_ERR)
		err("unable to replace SIGSEGV handler TERM");

	/* log("signal handler installed"); we've decided we don't need this anymore */
}

/*==============================================================================
| sig_handle()
| catch the signal, and deal with it correctly.  in general, this involves
| dying.  might be a good idea to use this to reload the config file
| rather than using DCP.  however, given the current implmentation, this 
| would require a module to receive a signal.  however, this is something we
| can probably do.  hrm.
==============================================================================*/

extern int line;	/* hack, formerly static variable in config.c */
void cleanup();		/* somewhere else, not quite as much of a hack */

static void
sig_handler(int sig)
{
	switch(sig) {
		case SIGTERM : log("termination signal"); break;
#ifdef SIGTRAP
		case SIGTRAP : log("trace/breakpoint trap"); break;
#endif
#ifdef SIGQUIT
		case SIGQUIT : log("keyboard quit"); break;
#endif
#ifdef SIGHUP
		case SIGHUP  : log("hangup detected"); break;
#endif
		case SIGINT  : log("interupt from keyboard"); break;

		case SIGSEGV : 
				log("invalid memory refrence");
			break;

		default: break;
	}
	clo();
	die(1, "caught signal %d, die", sig);
}
