/*==============================================================================
| options.h - parse command line options
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef OPTIONS_H
#define OPTIONS_H

extern int displayVersion;
extern int resolveHostnames;
extern char *configfile;

void parsecmdline(int argc, char *argv[]);
int booleanValue(char c);
void printusage();
void parseconfigline(char *buff);

#endif /* OPTIONS_H */
