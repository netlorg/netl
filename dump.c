/*==============================================================================
| dump.c
|   code by Graham THE Ollis <ollisg@ns.arizona.edu>
|
| this code is (c) 1997 Graham THE Ollis
|
|  dump.c has the hex file dump routines used by neta and xd
|  your free to modify and distribute this program as long as this header is
|  retained, source code is made *freely* available and you document your 
|  changes in some readable manner.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  23 Feb 97  G. Ollis	.92 created network analysis software
|  28 Feb 97  G. Ollis  took read() and dump() out of neta.c and put them
|			here.
|=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include "dump.h"

/*==============================================================================
| read
|=============================================================================*/

unsigned char *
read(char *fn, size_t *size, size_t max, char *prog)
{
  FILE		*fp;
  char		*buff;
  size_t	br;

  if((fp = fopen(fn, "r"))==NULL) {
    fprintf(stderr, "%s: warning: could not open %s, skipping\n", prog, fn);
    return NULL;
  }

  fseek(fp, 0, SEEK_END);
  *size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if(max != 0 && *size > max) {
    fprintf(stderr, "%s: warning: file %s is to big skipping\n",
		prog, fn);
    return NULL;
  }

  buff = (char *) malloc(*size);

  if((br=fread(buff, 1, *size, fp)) != *size) {
    fprintf(stderr, "%s: warning: error reading %s, skipping\n", prog, fn);
    fprintf(stderr, "%d != %d\n", br, *size);
    return NULL;
  }

  fclose(fp);

  return buff;
}

/*==============================================================================
| dumpdata
|=============================================================================*/

void dumpdata(unsigned char *data, size_t size)
{
  size_t offset = 0;
  int i;

  puts("data:");
  while(offset < size) {
    printf("  %04x ", offset);
    for(i=0; i<16 && offset+i < size; i++)
      printf("%02x ", data[offset+i]);
    while(i++<16)
      fputs("   ", stdout);
    for(i=0; i<16 && offset+i < size; i++)
      if(data[offset+i] > 31 && data[offset+i] <127)
        putchar(data[offset+i]);
      else
        putchar('.');
    putchar('\n');
    offset+=i;
  }
}
