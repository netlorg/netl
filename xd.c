/*==============================================================================
| xd
|   code by Graham THE Ollis <ollisg@ns.arizona.edu>
|
| this code is (c) 1997 Graham THE Ollis
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
|
|  xd hex dump of a file in a nice formated form, based on neta's hex dump
|  this is primarily a diagnostic tool for testing neta, but you may find
|  it useful, who knows.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  28 Feb 97  G. Ollis	.92 created program
|=============================================================================*/

char *id = "@(#)xd (c) 1997 graham the ollis <ollisg@ns.arizona.edu>";

#include <stdio.h>
#include <stdlib.h>
#include "dump.h"

/*==============================================================================
| main
|=============================================================================*/

int
main(int argc, char *argv[])
{
  int i;
  unsigned char *buff;
  size_t size;

  for(i=1; i<argc; i++) {
    if((buff=read(argv[i], &size, 0, argv[0]))!=NULL) {
      printf("%s:\n", argv[i]);
      dumpdata(buff, size);
      free(buff);
    }
  }

  return 0;
}

