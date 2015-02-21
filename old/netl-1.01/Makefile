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
CFLAGS=-O3 -Wall
#CFLAGS=-g3 -Wall
LDFLAGS=-L.

PREFIX=/usr/local
SUBINPATH=$(PREFIX)/sbin
BINPATH=$(PREFIX)/bin
SYSTEMMANPATH=$(PREFIX)/man/man8
USERMANPATH=$(PREFIX)/man/man1
LIBPATH=$(PREFIX)/lib
INCLUDEPATH=$(PREFIX)/include

NET_LIBS=
MISC_LIBS=

M4=m4
M4FLAGS=
COREDIR=tarquin.macro core.head core.line core.tail

#===============================================================================
# don't go below this line unless your in to that sort of thing
#===============================================================================

TDR=tdr
AR=ar
RANLIB=ranlib
LIB_NAME=netl
NETL_LIB=lib$(LIB_NAME).so.1.1
LIB_NETL=$(NETL_LIB)
LN=ln
VER=1.01
RM=rm -f
CP=cp
EXEC=netl neta xd hwpassive dcp
DIST=netl
PGP=pgp262

all:$(EXEC) $(LIB_NETL) lib$(LIB_NAME).a

gnr:all web dist

test:all
	cd t;$(TDR) tcp.t udp.t icmp.t resolve.t xd.t

dist:$(DIST)-$(VER).tar.gz $(DIST)-$(VER).tar.gz.sig \
     $(DIST)-$(VER)-bin.tar.gz $(DIST)-$(VER)-bin.tar.gz.sig \
     $(DIST)-$(VER).zip $(DIST)-$(VER).zip.sig 

%.gz:%
	gzip < $< > $@

%.sig:%
	$(PGP) -sb $<

$(DIST)-$(VER).zip:$(DIST)-$(VER).tar
	zip -r $(DIST)-$(VER).zip $(DIST)-$(VER)

$(DIST)-$(VER).tar:
	install -d $(DIST)-$(VER)
	cp -P `cat MANIFEST` $(DIST)-$(VER)
	tar cf $(DIST)-$(VER).tar $(DIST)-$(VER)

$(DIST)-$(VER)-bin.tar:$(EXEC)
	install -d $(DIST)-$(VER)-bin
	cp -P `cat MANIFEST.BIN` $(DIST)-$(VER)-bin
	tar cf $(DIST)-$(VER)-bin.tar $(DIST)-$(VER)-bin

#===============================================================================
# executables:
#===============================================================================

SOOBJ=resolve.o dump.o io.o
$(LIB_NETL):$(SOOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -shared -o $(LIB_NETL) $(SOOBJ)
	$(LN) -fs $(LIB_NETL) lib$(LIB_NAME).so.1
	$(LN) -fs $(LIB_NETL) lib$(LIB_NAME).so

lib$(LIB_NAME).a:$(SOOBJ)
	$(AR) cru lib$(LIB_NAME).a $(SOOBJ)
	$(RANLIB) lib$(LIB_NAME).a

NETLOBJ=netl.o sighandle.o config.o lookup.o options.o dcp.o grab.o parse.o dgprintf.o
netl:$(NETLOBJ) $(LIB_NETL)
	$(CC) $(LDFLAGS) $(CFLAGS) -o netl $(NETLOBJ) $(NET_LIBS) $(MISC_LIBS) -lnetl

HWPOBJ=hwpassive.o options.o sighandle.o
hwpassive:$(HWPOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o hwpassive $(HWPOBJ) $(NET_LIBS) $(MISC_LIBS) -lnetl

NETAOBJ=neta.o lookup.o options.o
neta:$(NETAOBJ) $(LIB_NETL)
	$(CC) $(LDFLAGS) $(CFLAGS) -o neta $(NETAOBJ) $(MISC_LIBS) -lnetl

XDOBJ=xd.o 
xd:$(XDOBJ) $(LIB_NETL)
	$(CC) $(LDFLAGS) $(CFLAGS) -o xd $(XDOBJ) $(MISC_LIBS) -lnetl

DCPOBJ=dcpclient.o
dcp:$(DCPOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o dcp $(DCPOBJ) $(MISC_LIBS) $(NET_LIBS) -lnetl

#===============================================================================
# object files:
#===============================================================================

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

hwpassive.o:hwpassive.c io.h global.h ether.h options.h config.h sighandle.h
netl.o:netl.c global.h ether.h netl.h sighandle.h io.h options.h config.h \
resolve.h ip.h parse.h grab.h
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
grab.o:grab.c grab.h io.h ether.h
parse.o:parse.c parse.h global.h ether.h ip.h config.h io.h resolve.h dcp.h \
dgprintf.h
dgprintf.o:dgprintf.c global.h ether.h ip.h io.h

#===============================================================================
# install:
#===============================================================================

.PHONY: install
install:
	install -d $(SUBINPATH)
	install -g 0 -o 0 -m 500 netl hwpassive $(SUBINPATH)
	install -d $(BINPATH)
	install -g 0 -o 0 -m 511 neta xd dcp.pl $(BINPATH)
	install -d -g 0 -o 0 -m 700 /tmp/netl
	install -d $(SYSTEMMANPATH) $(USERMANPATH)
	install -g 0 -o 0 -m 644 netl.8 $(SYSTEMMANPATH)
	install -g 0 -o 0 -m 644 hwpassive.8 $(SYSTEMMANPATH)
	install -g 0 -o 0 -m 644 neta.1 $(USERMANPATH)
	install -g 0 -o 0 -m 644 xd.1 $(USERMANPATH)
	install -g 0 -o 0 -m 644 dcp.1 $(USERMANPATH)
	install -d $(LIBPATH)
	install -g 0 -o 0 -m 755 $(NETL_LIB) $(LIBPATH)
	cd $(LIBPATH);$(LN) -fs $(NETL_LIB) lib$(LIB_NAME).so
	cd $(LIBPATH);$(LN) -fs $(NETL_LIB) lib$(LIB_NAME).so.1
	install -g 0 -o 0 -m 644 lib$(LIB_NAME).a $(LIBPATH)
	install -d $(INCLUDEPATH)/$(LIB_NAME)
	install -g 0 -o 0 -m 644 resolve.h dump.h io.h $(INCLUDEPATH)/$(LIB_NAME)

#===============================================================================
# clean:
#===============================================================================

.PHONY: clean
clean:
	$(RM) netl netl.exe neta neta.exe xd xd.exe hwpassive hwpassive.exe
	$(RM) dcp dcp.exe
	$(RM) tmp.dat core a.out 
	$(RM) *.o *.html *.tar *.tmp
	$(RM) -r $(DIST)-$(VER) $(DIST)-$(VER)-bin
	$(RM) t/*.diff t/*.diffERR t/*.ao t/*.aERR t/*.aRET
	$(RM) t/tdr.log t/core
	$(RM) lib*.so* lib*.a

distclean:clean
	$(RM) *.tar.gz *.zip *.sig

#===============================================================================
# web page
#===============================================================================

web:netl.html

netl.html:netl.html.m4 $(COREDIR)

%.html:%.html.m4
	$(M4) $(M4MACROS) $< > $@
