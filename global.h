/*==============================================================================
| global.h - macros everyone needs
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef GLOBAL_H
#define GLOBAL_H

#ifndef linux
  #error netl requires linux
#endif

#define COPYVER "0.92 (c) 1997 Graham THE Ollis <ollisg@ns.arizona.edu>"

#include <linux/types.h>

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;

#define TRUE			1
#define FALSE			0

extern char *prog;

#endif /* GLOBAL_H */
