/*==============================================================================
| dump.h - hex file dump routines used by neta and xd
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef DUMP_H
#define DUMP_H

unsigned char *read(char *fn, size_t *size, size_t max, char *prog);
void dumpdata(unsigned char *data, size_t size);

#endif
