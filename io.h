/*==============================================================================
| io.h - io module for deamon/forground class programs
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
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
==============================================================================*/

#ifndef IO_H
#define IO_H

void log(char *cp,...);		/* syslod()/printf() */
void err(char *cp,...);		/* syslog()/fprintf(stderr) */

void *allocate(size_t size);	/* malloc with protection */

#ifdef NO_SYSLOGD
  #define ope(s)
  #define clo()
#else
  void ope(char *s);		/* openlog/noop */
  void clo();			/* closelog/noop */
  extern int noBackground;
#endif

#ifndef NO_TEEOUT
  extern FILE *teefile;		/* -o file */
#endif

#endif
