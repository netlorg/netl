#@(#)slog Makefile (c) 1996 graham the ollis
#(c) 1997 Graham THE Ollis and CORE
#===============================================================================
# slog Makefile
#
# your free to modify and distribute this program as long as this header is
# retained, source code is made *freely* available and you document your 
# changes in some readable manner.
#
# A collection of nifty (and unusual) network loggers.  this is inspired by
# code written by  by Jeff Thompson <jwthomp@uiuc.edu>. 
# I felt the need to optimize and (in some cases) debug the code.  
#
# netl
#   a configurable network monitor/sniffer.  does just about everything 
#   a persons would want to do
#===============================================================================
#  Date       Name	Revision
#  ---------  --------  --------
#  01 Feb 97  G. Ollis	created Makefile (from old ones)
#  23 Feb 97  G. Ollis	modified for the new netl super log
#===============================================================================

VER=0.91

#===============================================================================
# the basics:
CC=gcc
CFLAGS=-m486 -O3 -Wall

#===============================================================================
# where pingl should be installed, so called super user bin directory:
SUBIN=/usr/local/sbin

## don't go below this line unless your in to that sort of thing
##==============================================================================

RM=rm -f
CP=cp

all:netl

dist:netl-$(VER).tar.gz

netl-$(VER).tar.gz:netl-$(VER).tar
	gzip < netl-$(VER).tar > netl-$(VER).tar.gz

netl-$(VER).tar:
	install -d netl-$(VER)
	cp `cat MANIFEST` netl-$(VER)
	tar cf netl-$(VER).tar netl-$(VER)

# executables:
netl:netl.o resolve.o sighandle.o config.o
	$(CC) $(CFLAGS) -o netl netl.o resolve.o sighandle.o config.o

# object files:
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

netl.o:netl.c sighandle.h netl.h

config.o:config.c netl.h

resolve.o:resolve.c netl.h

sighandle.o:sighandle.c sighandle.h

# install:
.PHONY: install
install:
	$(CP) netl $(SUBIN)
	chmod 500 $(SUBIN)/netl

# clean:
.PHONY: clean
clean:
	$(RM) *.o synl pingl netl core tmp.dat core a.out *.tar
	$(RM) -r netl-$(VER)


