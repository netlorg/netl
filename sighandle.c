/*==============================================================================
| sighandle.c
|   catch some simple signals 
|
| (c) 1997 Graham THE Ollis
|
|  Date       Name	Revision
|  ---------  --------  --------
|  08 Feb 97  G. Ollis	created
|=============================================================================*/

#include <signal.h>
#include <syslog.h>
#include "sighandle.h"

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
    syslog(LOG_WARNING, "unable to replace SIGTERM handler TERM");

  old_handler = signal(SIGTRAP, &sig_handler);
  if(old_handler == SIG_ERR)
    syslog(LOG_WARNING, "unable to replace SIGTERM handler TERM");

  syslog(LOG_NOTICE, "signal handler installed");
}

/*==============================================================================
| handle();
| install the signal handler.
==============================================================================*/

void
sig_handler(int sig)
{
  syslog(LOG_NOTICE, "caught signal %d, die", sig);
  exit(1);
}

