/*==============================================================================
| io.h - io module for deamon/forground class programs
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef IO_H
#define IO_H

#define TRUE			1
#define FALSE			0

void log(char *cp,...);
void err(char *cp,...);
extern int noBackground;

#endif
