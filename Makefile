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
# hwpassive
#   passively sniff IP packets for hardware addresses
#
# xd
#   simple diagnostic tool for dumping file in hex format to stdout
#===============================================================================
#  Date       Name	Revision
#  ---------  --------  --------
#  01 Feb 97  G. Ollis	created Makefile (from old ones)
#  23 Feb 97  G. Ollis	modified for the new netl super log
#  28 Feb 97  G. Ollis	updated stuff for .92 release
#  10 Mar 97  G. Ollis	updated stuff for .93 release
#  03 May 97  G. Ollis	began .94 release
#  05 Aug 97  G. Ollis	changed netl => $(DIST) for filenames and stuff
#===============================================================================

#===============================================================================
# here is the stuff you may be interested in changing.
#===============================================================================

CC=gcc
CFLAGS=-m486 -O3 -Wall
#CFLAGS=-g -Wall
SUBIN=/usr/local/sbin
BIN=/usr/local/bin
TDR=tdr
SYSTEMMAN=/usr/local/man/man8
USERMAN=/usr/local/man/man1
NET_LIBS=
MISC_LIBS=

#===============================================================================
# don't go below this line unless your in to that sort of thing
#===============================================================================

VER=0.95
RM=rm -f
CP=cp
EXEC=netl neta xd hwpassive dcp
DIST=netl

all:$(EXEC)

test:all
	cd t;$(TDR) tcp.t udp.t icmp.t resolve.t xd.t

dist:$(DIST)-$(VER).tar.gz $(DIST)-$(VER).tar.gz.sig $(DIST)-$(VER).zip $(DIST)-$(VER).zip.sig

$(DIST)-$(VER).zip.sig:$(DIST)-$(VER).zip
	pgp -sb $(DIST)-$(VER).zip

$(DIST)-$(VER).zip:$(DIST)-$(VER).tar
	zip -r $(DIST)-$(VER).zip $(DIST)-$(VER)

$(DIST)-$(VER).tar.gz.sig:$(DIST)-$(VER).tar.gz
	pgp -sb $(DIST)-$(VER).tar.gz

$(DIST)-$(VER).tar.gz:$(DIST)-$(VER).tar
	gzip < $(DIST)-$(VER).tar > $(DIST)-$(VER).tar.gz

$(DIST)-$(VER).tar:
	install -d $(DIST)-$(VER)
	cp -P `cat MANIFEST` $(DIST)-$(VER)
	tar cf $(DIST)-$(VER).tar $(DIST)-$(VER)

#===============================================================================
# executables:
#===============================================================================

HWPOBJ=hwpassive.o io.o options.o sighandle.o
hwpassive:$(HWPOBJ)
	$(CC) $(CFLAGS) -o hwpassive $(HWPOBJ) $(NET_LIBS) $(MISC_LIBS)
	strip hwpassive || true

NETLOBJ=netl.o resolve.o sighandle.o config.o lookup.o options.o io.o dcp.o
netl:$(NETLOBJ)
	$(CC) $(CFLAGS) -o netl $(NETLOBJ) $(NET_LIBS) $(MISC_LIBS)
	strip netl || true

NETAOBJ=neta.o resolve.o lookup.o options.o dump.o io.o
neta:$(NETAOBJ)
	$(CC) $(CFLAGS) -o neta $(NETAOBJ) $(MISC_LIBS)
	strip neta || true

XDOBJ=xd.o dump.o
xd:$(XDOBJ)
	$(CC) $(CFLAGS) -o xd $(XDOBJ) $(MISC_LIBS)
	strip xd || true

DCPOBJ=dcpclient.o io.o
dcp:$(DCPOBJ)
	$(CC) $(CFLAGS) -o dcp $(DCPOBJ) $(MISC_LIBS) $(NET_LIBS)
	strip dcp || true

#===============================================================================
# object files:
#===============================================================================

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

hwpassive.o:hwpassive.c io.h global.h ether.h options.h config.h sighandle.h
netl.o:netl.c global.h ether.h netl.h sighandle.h io.h options.h config.h \
resolve.h ip.h
neta.o:neta.c global.h ether.h dump.h lookup.h options.h resolve.h ip.h
xd.o:xd.c dump.h
dcp.o:dcp.c dcp.h global.h ether.h io.h config.h options.h resolve.h ip.h
io.o:io.c global.h io.h
dump.o:dump.c dump.h
lookup.o:lookup.c lookup.h global.h ether.h
config.o:config.c global.h ether.h config.h resolve.h lookup.h io.h options.h \
         ip.h
resolve.o:resolve.c global.h resolve.h io.h
sighandle.o:sighandle.c sighandle.h io.h global.h
options.o:options.c global.h config.h options.h io.h
dcpclient.o:dcpclient.c global.h io.h

#===============================================================================
# install:
#===============================================================================

.PHONY: install
install:
	strip $(EXEC)
	install -d $(SUBIN)
	install -g 0 -o 0 -m 500 netl hwpassive $(SUBIN)
	install -d $(BIN)
	install -g 0 -o 0 -m 511 neta xd $(BIN)
	install -d -g 0 -o 0 -m 700 /tmp/netl
	install -g 0 -o 0 -m 644 netl.8 $(SYSTEMMAN)
	install -g 0 -o 0 -m 644 hwpassive.8 $(SYSTEMMAN)
	install -g 0 -o 0 -m 644 neta.1 $(USERMAN)
	install -g 0 -o 0 -m 644 xd.1 $(USERMAN)
	install -g 0 -o 0 -m 644 dcp.1 $(USERMAN)

#===============================================================================
# clean:
#===============================================================================

.PHONY: clean
clean:
	$(RM) *.o netl netl.exe neta neta.exe xd xd.exe hwpassive hwpassive.exe
	$(RM) dcp dcp.exe
	$(RM) tmp.dat core a.out *.tar
	$(RM) -r $(DIST)-$(VER) t/*.diff t/*.diffERR t/*.ao t/*.aERR t/*.aRET
	$(RM) t/tdr.log t/core

distclean:clean
	$(RM) *.tar.gz *.zip *.sig
