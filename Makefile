#@(#)netl/neta Makefile (c) 1996, 1997 graham the ollis
#(c) 1997 Graham THE Ollis and CORE
#===============================================================================
# netl/neta Makefile
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
#
# neta
#   a network datagram analizer handy for inspecting those files which you
#   have made using the dump action
#
# xd
#   simple diagnostic tool for dumping file in hex format to stdout
#===============================================================================
#  Date       Name	Revision
#  ---------  --------  --------
#  01 Feb 97  G. Ollis	created Makefile (from old ones)
#  23 Feb 97  G. Ollis	modified for the new netl super log
#  28 Feb 97  G. Ollis	updated stuff for .92 release
#===============================================================================

#===============================================================================
# here is the stuff you may be interested in changing.
#===============================================================================

CC=gcc
CFLAGS=-m486 -O3 -Wall
SUBIN=/usr/local/sbin
BIN=/usr/local/bin

#===============================================================================
# don't go below this line unless your in to that sort of thing
#===============================================================================

VER=0.92
RM=rm -f
CP=cp

all:netl neta xd

test:all
	cd t;tdr tcp.t udp.t icmp.t resolve.t xd.t

dist:netl-$(VER).tar.gz netl-$(VER).tar.gz.sig

netl-$(VER).tar.gz.sig:netl-$(VER).tar.gz
	pgp -sb netl-$(VER).tar.gz

netl-$(VER).tar.gz:netl-$(VER).tar
	gzip < netl-$(VER).tar > netl-$(VER).tar.gz

netl-$(VER).tar:
	install -d netl-$(VER)
	cp -P `cat MANIFEST` netl-$(VER)
	tar cf netl-$(VER).tar netl-$(VER)

# executables:
netl:netl.o resolve.o sighandle.o config.o lookup.o options.o io.o
	$(CC) $(CFLAGS) -o netl netl.o resolve.o sighandle.o config.o lookup.o \
options.o io.o

neta:neta.o resolve.o lookup.o options.o dump.o
	$(CC) $(CFLAGS) -o neta neta.o resolve.o lookup.o options.o dump.o

xd:xd.o dump.o
	$(CC) $(CFLAGS) -o xd xd.o dump.o

# object files:
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

netl.o:netl.c global.h ether.h netl.h sighandle.h io.h options.h config.h resolve.h
neta.o:neta.c global.h ether.h dump.h lookup.h options.h resolve.h
xd.o:xd.c dump.h

io.o:io.c io.h
dump.o:dump.c dump.h
lookup.o:lookup.c lookup.h global.h ether.h
config.o:config.c global.h ether.h config.h resolve.h lookup.h 
resolve.o:resolve.c global.h resolve.h
sighandle.o:sighandle.c sighandle.h io.h
options.o:options.c global.h config.h options.h io.h

# install:
.PHONY: install
install:
	install -d $(SUBIN)
	install -g 0 -o 0 -m 500 netl $(SUBIN)
	install -d $(BIN)
	install -g 0 -o 0 -m 511 neta xd $(BIN)
	install -d -g 0 -o 0 -m 700 /tmp/netl

# clean:
.PHONY: clean
clean:
	$(RM) *.o synl pingl netl neta core tmp.dat core a.out *.tar
	$(RM) -r netl-$(VER) t/*.diff t/*.diffERR t/*.ao t/*.aERR t/*.aRET
	$(RM) t/tdr.log t/core xd


