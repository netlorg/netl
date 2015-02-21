/*==============================================================================
| io.h - io module for deamon/forground class programs
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@netl.org>
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
==============================================================================*/

#ifndef NETL_IO_H
#define NETL_IO_H

void netl_io_log(char *cp,...);		/* syslod()/printf() */
void netl_io_err(char *cp,...);		/* syslog()/fprintf(stderr) */
void netl_io_die(int, char *,...);

void *netl_io_allocate(size_t size);	/* malloc with protection */

#ifdef NO_SYSLOGD
  #define ope(s)		/* it's the amazing do nothing function */
  #define clo()			/* actually this is even more amazing,
				   it does nothing with nothing!	*/
#else
  void netl_io_ope(char *s);		/* openlog/noop */
  void netl_io_clo();			/* closelog/noop */
  #define ope(derf) netl_io_ope(derf)
  #define clo() netl_io_clo()
  extern int netl_guts_noBackground;
  #define noBackground netl_guts_noBackground
#endif

#ifndef NO_TEEOUT
  extern FILE *netl_guts_teefile;		/* -o file */
  #define teefile netl_guts_teefile
#endif

void *netl_nmopen(char *name);
int netl_nmclose(void *handle);
void *netl_nmsym(void *handle, char *symbol);
void *netl_nmsym_nofail(void *handle, char *symbol);

int netl_io_ahextoi(char *s);

#define log netl_io_log
#define err netl_io_err
#define die netl_io_die
#define allocate(fred) netl_io_allocate(fred)
#define nmopen(derf) netl_nmopen(derf)
#define nmclose(derf) netl_nmclose(derf)
#define nmsym(derf, fred) netl_nmsym(derf, fred)
#define nmsym_nofail(derf, fred) netl_nmsym_nofail(derf, fred)
#define ahextoi(derf) netl_io_ahextoi(derf)

#endif
