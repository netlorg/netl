/*==============================================================================
| options.h - parse command line options
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@wwa.com>
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
==============================================================================*/

#ifndef OPTIONS_H
#define OPTIONS_H

extern int displayVersion;
extern int resolveHostnames;
extern int debug_mode;
extern int useIPv6;
extern char *configfile;
extern char *netdevice;
extern char *dump_dir;

void parsecmdline(int argc, char *argv[]);
int booleanValue(char c);
void printusage();
void parseconfigline(char *buff);

extern int output_mode;
extern char *output_name;
#define OUT_MODE_NORM	0
#define OUT_MODE_C	1

#endif /* OPTIONS_H */
