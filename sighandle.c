/*==============================================================================
| sighandle.c
|   catch some simple signals 
|
| (c) 1997 Graham THE Ollis
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  08 Feb 97  G. Ollis	created
|  28 Feb 97  G. Ollis	.92 output can go to stdout or syslog depending on
|			how netl is called.
|=============================================================================*/

#include <signal.h>
#include "sighandle.h"
#include "io.h"

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

  old_handler = signal(SIGTRAP, &sig_handler);
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

  log("signal handler installed");
}

/*==============================================================================
| handle();
| install the signal handler.
==============================================================================*/

void
sig_handler(int sig)
{
  log("caught signal %d, die", sig);
  exit(1);
}

