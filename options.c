/*==============================================================================
| options.c
|   parse the command line options for the netl/neta project
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
int debug_mode = FALSE;
char netdevice[255] = "eth0";

char *configfile = NETL_CONFIG;

/*==============================================================================
| open another output file
| only for the -o option
|=============================================================================*/

#ifndef NO_TEEOUT
void
openteefile(char *s)
{
  teefile = fopen(s, "a");
  if(teefile == NULL) {
    fprintf(stderr, "%s: error opening %s for append\n", prog, s);
    exit(1);
  }
}
#endif


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

#ifndef NO_SYSLOGD
        case 'z' :
          noBackground = booleanValue(argv[0][2]);
	  break;
#endif

#ifndef NO_TEEOUT
	case 'o' :
          openteefile(&argv[0][2]);
	  break;
#endif

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

	case 'd' :
	  debug_mode = 1;
	  break;

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
  puts("usage: netl [options] [requirements]
usage: neta [options] [datagram-file]

where options can be any of the following:
-v   display version number copyright information [on]
-r   resolve IP numbers to hostname [on]
-f   set config file [/etc/netl.conf]
-d   print out configeration and DON\'T run (debug option)
-h   this help message");
#ifndef NO_SYSLOGD
  puts("-z   do not run in background, send all output to STDOUT and STDERR");
#endif
#ifndef NO_TEEOUT
  puts("-o   send a copy of output to specified file");
#endif
  puts("
defaults are in the [].  to turn off an option append a -,
to turn on append a +.  the default is +, so to turn version
display off, pass \"-v-\" as a command line argument.

for -f:  use -ffilename to set config file to filename, or
-f by itself to force netl not to read a config file");
}
