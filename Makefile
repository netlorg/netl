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
#  10 Mar 97  G. Ollis	updated stuff for .93 release
#  03 May 97  G. Ollis	began .94 release
#  05 Aug 97  G. Ollis	changed netl => $(DIST) for filenames and stuff
#===============================================================================

include Makefile.inc

#===============================================================================
# don't go below this line unless your in to that sort of thing
#===============================================================================

CFLAGS+=-I include
TDR=../tdr.pl
EXEC=netl neta xd hwpassive hwlookup
DIST=netl

MOD=in.nmod filt.nmod out.nmod

all : include/netl/version.h $(EXEC) $(MOD) libnetl.so

hwpassive:
	echo "#!/bin/sh" > hwpassive
	echo "$(SUBINPATH)/netl \$$* 'null &hwpassive'" >> hwpassive
	chmod +x hwpassive

%.nmod:
	cd $*;$(MAKE)

gnr:all web dist

test:all
	cd t;$(TDR) -n *.t

dist:README INSTALL MANIFEST.BIN doc.nmod Makefile.dep $(DIST)-$(VER).tar.gz tdr-$(TDR_VER).tar.gz

sigs:$(DIST)-$(VER).tar.gz.sig \
     $(DIST)-$(VER)-bin.tar.gz $(DIST)-$(VER)-bin.tar.gz.sig \
     $(DIST)-$(VER).zip $(DIST)-$(VER).zip.sig 

MANIFEST.BIN:MANIFEST
	$(CP) MANIFEST MANIFEST.BIN
	echo 'MANIFEST.BIN' >> MANIFEST.BIN
	echo 'netl' >> MANIFEST.BIN
	echo 'neta' >> MANIFEST.BIN
	echo 'xd' >> MANIFEST.BIN
	find -name \*.so -print >> MANIFEST.BIN

README INSTALL:
	cd doc;$(MAKE)
	cp doc/netl.8.txt README
	cp doc/netl_install.1.txt INSTALL

%.gz:%
	gzip < $< > $@

%.sig:%
	$(PGP) -sb $<

$(DIST)-$(VER).zip:$(DIST)-$(VER).tar
	zip -r $(DIST)-$(VER).zip $(DIST)-$(VER)

tdr-$(TDR_VER).tar:
	install -d tdr-$(TDR_VER)
	cp tdr.pl doc/tdr.1 tdr-$(TDR_VER)
	tar cf tdr-$(TDR_VER).tar tdr-$(TDR_VER)

$(DIST)-$(VER).tar:
	install -d $(DIST)-$(VER)
	cp -aP `cat MANIFEST` $(DIST)-$(VER)
	tar cf $(DIST)-$(VER).tar $(DIST)-$(VER)

$(DIST)-$(VER)-bin.tar:$(EXEC) $(MOD)
	install -d $(DIST)-$(VER)-bin
	cp -P `cat MANIFEST.BIN` $(DIST)-$(VER)-bin
	cd $(DIST)-$(VER)-bin; rm default.so; ln -s linux-ether.so default.so
	tar cf $(DIST)-$(VER)-bin.tar $(DIST)-$(VER)-bin

#===============================================================================
# executables:
#===============================================================================

NETLOBJ=netl.o sighandle.o config.tab.o lex.yy.o lookup.o options.o check.o \
filter.o action.o resolve.o dump.o io.o compiler.o ipv6.o main.o
netl:$(NETLOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o netl $(NETLOBJ) $(NET_LIBS) $(MISC_LIBS) $(LEX_LIBS) $(YACC_LIBS)

HWLOOKUPOBJ=hwlookup.o options.o resolve.o io.o
hwlookup:$(HWLOOKUPOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o hwlookup $(HWLOOKUPOBJ) $(MISC_LIBS)

NETAOBJ=neta.o lookup.o options.o resolve.o dump.o io.o
neta:$(NETAOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o neta $(NETAOBJ) $(MISC_LIBS)

XDOBJ=xd.o resolve.o dump.o io.o
xd:$(XDOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o xd $(XDOBJ) $(MISC_LIBS)

LIBOBJ=action.o check.o compiler.o dump.o filter.o \
io.o ipv6.o lookup.o options.o resolve.o \
sighandle.o lex.yy.o config.tab.o netl.o catch.o
libnetl.a:$(LIBOBJ)
	$(AR) rc libnetl.a $(LIBOBJ)
	$(RANLIB) libnetl.a

libnetl.so:$(LIBOBJ)
	$(CC) -shared $(LDFLAGS) $(CFLAGS) -o libnetl.so $(LIBOBJ)

#===============================================================================
# object files:
#===============================================================================

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# scanner
#

lex.yy.o: lex.yy.c config.tab.h 

lex.yy.c:config.l config.tab.h
	$(LEX) $(LEXFLAGS) config.l

#
# parser
#

config.tab.o:config.tab.h config.tab.c

config.tab.h config.tab.c:config.y
	$(YACC) $(YACCFLAGS) config.y

#===============================================================================
# install:
#===============================================================================

.PHONY: install
install:
	install -d $(LIBPATH)
	install -d $(LIBPATH)/sbin
	install -g 0 -o 0 -m 511 netl $(LIBPATH)/sbin
	install -g 0 -o 0 -m 555 hwpassive $(LIBPATH)/sbin
	install -d $(SUBINPATH)
	cd $(SUBINPATH);$(RM) netl hwpassive
	cd $(SUBINPATH);ln $(LIBPATH)/sbin/* . || cp $(LIBPATH)/sbin/* .
	install -d $(LIBPATH)/bin
	install -g 0 -o 0 -m 511 neta xd $(LIBPATH)/bin
	install -g 0 -o 0 -m 555 dcp.pl $(LIBPATH)/bin/dcp
	install -g 0 -o 0 -m 555 tdr.pl $(LIBPATH)/bin/tdr
	install -g 0 -o 0 -m 555 hwlookup $(LIBPATH)/bin
	install -g 0 -o 0 -m 555 netlcc.pl $(LIBPATH)/bin/netlcc
	install -d $(BINPATH)
	cd $(BINPATH);$(RM) neta xd dcp tdr hwlookup netlcc
	cd $(BINPATH);ln $(LIBPATH)/bin/* . || cp $(LIBPATH)/bin/* .
	install -d $(LIBPATH)/man/man1 $(LIBPATH)/man/man5 $(LIBPATH)/man/man8
	install -g 0 -o 0 -m 644 doc/*.1 $(LIBPATH)/man/man1
	install -g 0 -o 0 -m 644 doc/*.5 $(LIBPATH)/man/man5
	install -g 0 -o 0 -m 644 doc/*.8 $(LIBPATH)/man/man8
	install -d $(MANPATH) $(MANPATH)/man1 $(MANPATH)/man5 $(MANPATH)/man8
	cd $(MANPATH)/man1; ln -f $(LIBPATH)/man/man1/* . || cp $(LIBPATH)/man/man1 .
	cd $(MANPATH)/man5; ln -f $(LIBPATH)/man/man5/* . || cp $(LIBPATH)/man/man5 .
	cd $(MANPATH)/man8; ln -f $(LIBPATH)/man/man8/* . || cp $(LIBPATH)/man/man8 .
	$(RM) -r $(PREFIX)/lib/netl
	ln -s $(LIBPATH) $(PREFIX)/lib/netl
	install -d $(LIBPATH)/dump
	install -d $(INCLUDEPATH)/netl
	install -g 0 -o 0 -m 644 include/netl/*.h $(INCLUDEPATH)/netl
	install -g 0 -o 0 -m 755 libnetl.so $(LIBPATH)
	install -g 0 -o 0 -m 644 hwcode $(LIBPATH)
	cd in; $(MAKE) install
	cd out; $(MAKE) install
	cd filt; $(MAKE) install

#===============================================================================
# clean:
#===============================================================================

.PHONY: clean
clean:
	$(RM) netl netl.exe neta neta.exe xd xd.exe hwlookup hwlookup.exe
	$(RM) dcp dcp.exe
	$(RM) tmp.dat core a.out 
	$(RM) *.o *.html *.tar *.tmp
	$(RM) -r $(DIST)-$(VER) $(DIST)-$(VER)-bin tdr-$(TDR_VER)
	$(RM) t/*.diff t/*.diffERR t/*.diffRET t/*.ao t/*.aERR t/*.aRET
	$(RM) t/tdr.log t/core
	$(RM) lib*.so* lib*.a tdr.log
	$(RM) lex.yy.c config.tab.h config.tab.c config.output config_test
	$(RM) userfilter.c *.so README INSTALL conf/*.c conf/*.so conf/*.o
	$(RM) *.a *.so hwpassive hwpassive.exe configure.out
	cd in; $(MAKE) clean
	cd filt; $(MAKE) clean
	cd out; $(MAKE) clean

distclean:clean

realclean:clean
	$(RM) *.tar.gz *.zip *.sig MANIFEST.BIN
	$(RM) Makefile.dep */Makefile.dep include/netl/version.h
	cd doc; $(MAKE) clean

wc:
	wc -l *.{c,y,l,pl} include/netl/*.h {in,filt,out}/*.{c,h} |sort -n | tee .wc

Makefile.dep:
	$(PERL) makedepend.pl

Makefile.inc include/netl/version.h :
	./configure

include Makefile.dep
