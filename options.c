/*==============================================================================
| options.c
|   parse the command line options for the netl/neta project
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
|  28 Feb 97  G. Ollis	created
|  02 Jul 99  G. Ollis	corrected spelling for --foreground
|=============================================================================*/

#include <stdlib.h>
#include <stdio.h>

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/netl.h"
#include "netl/global.h"
#include "netl/filter.h"
#include "netl/action.h"
#include "netl/config.h"
#include "netl/options.h"
#include "netl/io.h"

/*==============================================================================
| global "options" 
|=============================================================================*/

char *so_path_default = NETL_LIB_PATH;
char *so_path = NETL_LIB_PATH;
char *grab_module_name = "default";
char *dump_dir = NETL_LIB_PATH "/dump";

int displayVersion = TRUE;
int useIPv6 = FALSE;
int debug_mode = FALSE;
int output_mode = 0;
char *output_name = "userfilter.c";
char *netdevice = "eth0";

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
		/*printf("%d:%s\n", argc, argv[0]);*/
		if(argv[0][0] == '-') {

			/*========================================================================
			| it's an option
			|=======================================================================*/

			if(argv[0][1] == '-') {		/* long options... */
				if(!strcmp("--foreground", argv[0]))
					noBackground = 1;
				else if(!strcmp("--background", argv[0]))
					noBackground = 0;
				else if(!strcmp("--resolve", argv[0]))
					resolveHostnames = 1;
				else if(!strcmp("--dont-resolve", argv[0]))
					resolveHostnames = 0;
				else if(!strcmp("--debug", argv[0]))
					debug_mode = 1;
				else if(!strcmp("--tee", argv[0])) {
					openteefile(argv[1]); argv[1] = "-";
					argv++;  argc--;
				} else if(!strcmp("--help", argv[0])) {
					printusage();
					exit(1);
				} else if(!strcmp("--file", argv[0])) {
					configfile = argv[1]; argv[1] = "-";
					argv++;  argc--;
				} else if(!strcmp("--lib-dir", argv[0])) {
					so_path = argv[1]; argv[1] = "-";
					argv++;  argc--;
				} else if(!strcmp("--input", argv[0])) {
					grab_module_name = argv[1]; 
					argv[1] = "-";
					argv++;  argc--;
				} else if(!strcmp("--generate-c", argv[0])) {
					output_mode = OUT_MODE_C;
				} else if(!strcmp("--stdout", argv[0])) {
					output_mode = OUT_MODE_C;
					output_name = "-";
				} else if(!strcmp("--output-name", argv[0])) {
					output_name = argv[1]; argv[1] = "-";
					argv++; argc--;
				} else if(!strcmp("--dump-dir", argv[0])) {
					dump_dir = argv[1]; argv[1] = "-";
					argv++; argc--;
				} else
					fprintf(stderr, "%s: warning: unknown option %s, use -h for help\n",
									prog, argv[0]);
			} else switch(argv[0][1]) {


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

				case '6' :
					useIPv6 = booleanValue(argv[0][2]);
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

				case 'L' :
					if(argv[0][2] == 0)
						so_path = so_path_default;
					else
						so_path = &argv[0][2];
					break;

				case 'i' :
					grab_module_name = &argv[0][2];
					break;

				case 'h' :
					printusage();
					exit(1);

				case 'd' :
					debug_mode = booleanValue(argv[0][2]);
					break;

				default :
					fprintf(stderr, "%s: warning: unknown option %s, use -h for help\n",
									prog, argv[0]);
					break;

			}
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
-v			display version number copyright information [on]
-r, --resolve		resolve IP numbers to hostname [on]
    --dont-resolve	do not resolve
-f, --file		set config file [/etc/netl.conf]
-d, --debug		print out configeration and DON\'T run (debug option)
-h, --help		this help message
-i, --input		module to use for input
-L, --lib-dir		directory to load dynamic netl modules from
    --generate-c	instead of running as a daemon process, generate c 
			code for a netl module equivalent to the given
			configeration.
    --output-name	change the name of the c file output using the
			--generate-c option.  the default is userfilter.c
    --dump-dir		specify a directory to put the packet dumps into.
			by default, this is /usr/local/lib/netl/dump
    --stdout		a combination of --generate-c and --output-name which
			sends the netl module c code to stdout.
-6			use experimental IPv6 filters.  (off by default)\n");
#ifndef NO_SYSLOGD
	puts(
"-z, --foreground		do not run in background, send all output to STDOUT and STDERR
    --background	run in the background, send all output to syslogd");
#endif
#ifndef NO_TEEOUT
	puts(
"-o, -tee 		send a copy of output to specified file");
#endif
	puts("
defaults are in the [].  for single character options, 
turn off an option append a -, to turn on append a +.  
the default is +, so to turn version display off, 
pass \"-v-\" as a command line argument.

for -f:  use -ffilename to set config file to filename, or
-f by itself to force netl not to read a config file.");
}
