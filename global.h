/*==============================================================================
| global.h - macros everyone needs
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

#ifndef GLOBAL_H
#define GLOBAL_H

/*==============================================================================
| start configure
==============================================================================*/

/*==============================================================================
| NO_SYSLOGD
|
| on unix system, output get's sent to syslogd by default.  this can be 
| overridden using the -z option.  on non unix (win32) systems define 
| NO_SYSLOGD to optamize the output code.
==============================================================================*/

#undef NO_SYSLOGD

/*==============================================================================
| NO_TEEOUT
|
| on unix system, you can send out put to a file using redirection and then
| use tail -f to monitor the output.  on windows system, files stay at a size 
| of zero until they are closed.  with NO_TEEOUT you can use the -o option to
| copy a duplicate to a file and monitor stdout.  ok, that was confusing.
|
| unix# netl -z | tee netl.log
|
| is the same as this in win95:
|
| c:> netl -onetl.log
|
| though this only works with NO_TEEOUT.  there is no reason to define it
| unless your windows.  the default for win32 is #undef NO_TEEOUT
==============================================================================*/

/*#define NO_TEEOUT*/

/*==============================================================================
| end configure (hopefully this is far as you need to go)
==============================================================================*/

#define COPYVER "1.01 copyright 1997 Graham THE Ollis <ollisg@wwa.com>"

#ifndef TRUE
  #define TRUE			1
#endif
#ifndef FALSE
  #define FALSE			0
#endif

extern char *prog;

/*==============================================================================
| linux 32 bit tested on a modified (stealth) 2.0.29 kernel
==============================================================================*/

#ifdef linux

  #include <netinet/in.h>
/*  #include <linux/types.h> */
  #include <linux/if_ether.h> 
/*  #include <asm/byteorder.h> */
  #include <sys/types.h>
  #include <endian.h>

  typedef u_int8_t	u8;
  typedef u_int16_t	u16;
  typedef u_int32_t	u32;

/*  #if defined __LITTLE_ENDIAN_BITFIELD*/
  #if __BYTE_ORDER == __LITTLE_ENDIAN
    #ifndef LITTLE_ENDIAN
      #define LITTLE_ENDIAN
    #endif
/*  #elif defined __BIG_ENDIAN_BITFIELD*/
  #elif __BTE_ORDER == __BIG_ENDIAN
    #ifndef BIG_ENDIAN
      #define BIG_ENDIAN
    #endif
  #else
    #error "cannot determine byte order!"
  #endif

  #define NETL_LOG_FACILITY	LOG_LOCAL4

  #define OS_UNIX

/*==============================================================================
| gnu for win32 tested on the win95 of the same machine
| NEEDS ALL SORTS OF WORK
|
| the values marked as coming from linux come from a linux kernel and
| don't work
==============================================================================*/

#elif __CYGWIN32__

  #include <asm/types.h>

  typedef __u8	u8;
  typedef __u16 u16;
  typedef __u32 u32;

  #define LITTLE_ENDIAN
/* this doesn't work
  #define ETH_P_ALL		0x0003		// linux/if_ether.h 
  #define SIOCSIFFLAGS		0x8914		// linux/sockios.h
*/

  #define NETL_LOG_FACILITY	LOG_USER

  #define OS_WIN32
  #define NO_SYSLOGD
  #undef  NO_TEEOUT

/*==============================================================================
| DJGPP gnu for 32bit dos.  this is totally unexpected to work
|
| in this case i am atempting to cross compile from linux (same as above)
==============================================================================*/

#elif __DJGPP__

  typedef unsigned char		u8;
  typedef unsigned short	u16;
  typedef unsigned int		u32;

  #define LITTLE_ENDIAN

  #define NETL_LOG_FACILITY	LOG_USER

  #define OS_WIN32
  #define NO_SYSLOGD
  #undef  NO_TEEOUT

#else
  #error "your operating system isn't defined in global.h"
#endif

#endif /* GLOBAL_H */
