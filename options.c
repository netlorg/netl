/*==============================================================================
| options.c
|   parse the command line options for the netl/neta project
|
| (c) 1997 Graham THE Ollis
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  28 Feb 97  G. Ollis	created
|=============================================================================*/

#include <stdlib.h>
#include <stdio.h>

#include "global.h"
#include "config.h"
#include "options.h"
#include "io.h"

/*==============================================================================
| global "options" 
|=============================================================================*/

int displayVersion = TRUE;
int resolveHostnames = TRUE;

char *configfile = NETL_CONFIG;

/*==============================================================================
| parse the command line
|=============================================================================*/

void
parsecmdline(int argc, char *argv[])
{
  while(--argc > 0) {
    argv++;
    if(argv[0][0] == '-') 

      /*========================================================================
      | it's an option
      |=======================================================================*/

      switch(argv[0][1]) {
        case 'z' :
          noBackground = booleanValue(argv[0][2]);

        case 'v' :
          displayVersion = booleanValue(argv[0][2]);
          break;

        case 'r' :
          resolveHostnames = booleanValue(argv[0][2]);
          break;

        case 'f' :
          if(argv[0][2] == 0)
            configfile = NULL;
          else
            configfile = &argv[0][2];
          break;

        case 'h' :
          printusage();
          exit(1);

        default :
          fprintf(stderr, "%s: warning: unknown option %s, use -h for help\n",
                  prog, argv[0]);
          break;

      }
  }
}

/*==============================================================================
| figure out if the user is wanting to turn on or off the boolean option.
| default=+, + = on, - = off
|=============================================================================*/

int
booleanValue(char c)
{
  switch(c) {
    case '+' : case 0 :
      return TRUE;

    case '-' :
      return FALSE;

    default :
      fprintf(stderr, "%s: warning: boolean options should be followed by + or -\n", prog);
      return TRUE;
  }
}

/*==============================================================================
| print usage information (-h option)
|=============================================================================*/

void
printusage()
{
  puts("usage: netl [options] [requirements]");
  puts("usage: neta [options] [datagram-file]");
  putchar('\n');
  puts("where options can be any of the following:");
  puts("-v   display version number copyright information [on]");
  puts("-r   resolve IP numbers to hostname [on]");
  puts("-f   set config file [/etc/netl.conf]");
  puts("-z   do not run in background, send all output to STDOUT and STDERR");
  puts("-h   this help message");
  putchar('\n');
  puts("defaults are in the [].  to turn off an option append a -,");
  puts("to turn on append a +.  the default is +, so to turn version");
  puts("display off, pass \"-v-\" as a command line argument.");
  putchar('\n');
  puts("for -f:  use -ffilename to set config file to filename, or");
  puts("-f by itself to force netl not to read a config file");
}
