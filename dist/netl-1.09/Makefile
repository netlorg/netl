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

all : include/netl/version.h $(EXEC) $(MOD) libnetl.so netlcc.sh dcp.pl

hwpassive:
	echo "#!/bin/sh" > hwpassive
	echo "$(SUBINPATH)/netl \$$* 'null &hwpassive'" >> hwpassive
	chmod +x hwpassive

%.nmod:
	cd $*;$(MAKE)

gnr:all web dist

test:all
	cd t;$(TDR) -n *.t

dist:README INSTALL doc.nmod Makefile.dep \
	$(DIST)-$(VER).tar.gz tdr-$(TDR_VER).tar.gz

sigs:$(DIST)-$(VER).tar.gz.sig

README INSTALL:
	cd doc;$(MAKE)
	cp doc/netl.8.txt README
	cp doc/netl_install.1.txt INSTALL

%.gz:%
	gzip < $< > $@

%.sig:%
	$(PGP) -sb $<

zip:$(DIST)-$(VER).zip

.PHONY: $(DIST)-$(VER).zip
$(DIST)-$(VER).zip:
	zip -r $(DIST)-$(VER).zip $(DIST)-$(VER)

tdr-$(TDR_VER).tar:
	install -d tdr-$(TDR_VER)
	cp tdr.pl doc/tdr.1 tdr-$(TDR_VER)
	tar cf tdr-$(TDR_VER).tar tdr-$(TDR_VER)

.PHONY: $(DIST)-$(VER).tar
$(DIST)-$(VER).tar:
	install -d $(DIST)-$(VER)
	cp -aP `cat MANIFEST` $(DIST)-$(VER)
	tar cf $(DIST)-$(VER).tar $(DIST)-$(VER)

#===============================================================================
# executables:
#===============================================================================

NETLOBJ=netl.o sighandle.o config.tab.o lex.yy.o lookup.o options_netl.o check.o \
filter.o action.o resolve.o dump.o io.o compiler.o ipv6.o die_trickle.o main.o
netl:$(NETLOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o netl $(NETLOBJ) $(NET_LIBS) $(MISC_LIBS) $(LEX_LIBS) $(YACC_LIBS)

HWLOOKUPOBJ=hwlookup.o options_hwlookup.o resolve.o io.o die_blank.o
hwlookup:$(HWLOOKUPOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o hwlookup $(HWLOOKUPOBJ) $(MISC_LIBS)

NETAOBJ=neta.o lookup.o options_neta.o resolve.o dump.o io.o die_blank.o
neta:$(NETAOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o neta $(NETAOBJ) $(MISC_LIBS)

XDOBJ=xd.o resolve.o dump.o io.o die_blank.o
xd:$(XDOBJ)
	$(CC) $(LDFLAGS) $(CFLAGS) -o xd $(XDOBJ) $(MISC_LIBS)

LIBOBJ=action.o check.o compiler.o dump.o filter.o \
io.o ipv6.o lookup.o options_netl.o resolve.o \
sighandle.o lex.yy.o config.tab.o netl.o catch.o die_trickle.o
libnetl.a:$(LIBOBJ)
	$(AR) rc libnetl.a $(LIBOBJ)
	$(RANLIB) libnetl.a

libnetl.so:$(LIBOBJ)
	$(CC) -shared $(LDFLAGS) $(CFLAGS) -o libnetl.so $(LIBOBJ)

#===============================================================================
# object files:
#===============================================================================

options_netl.o:options.c
	$(CC) $(CFLAGS) -DOPTIONS_NETL -c options.c -o options_netl.o

options_neta.o:options.c
	$(CC) $(CFLAGS) -DOPTIONS_NETA -c options.c -o options_neta.o

options_hwlookup.o:options.c
	$(CC) $(CFLAGS) -DOPTIONS_HWLOOKUP -c options.c -o options_hwlookup.o

die_trickle.o:die.c
	$(CC) $(CFLAGS) -DDIE_TRICKLE -c die.c -o die_trickle.o

die_blank.o:
	$(CC) $(CFLAGS) -c die.c -o die_blank.o

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

%:%.exe
	./$<
	chmod +x $@

netlcc.sh:netlcc.sh.exe
	./netlcc.sh.exe
	chmod +x netlcc.sh

%.exe:%.exe.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $<

#
# scanner
#

lex.yy.o: lex.yy.c config.tab.h 

lex.yy.c:config.l config.tab.h
	$(LEX) $(LEXFLAGS) config.l

#
# parser
#

pp:face/perltk/face/Netl/Config/Parser.pm

# this here is a haxor of supreme dimensions.
#
# config.y contains the parser for libnetl and the netl executable, in
# addition to the perl version of the parser used by tknetl.  right now there
# are macros NETL_CONFIG_Y_C and NETL_CONFIG_Y_PERL to indicate the language
# as appropriate.  however, the C version uses bison and the perl version uses
# a specially modified version of byacc.  joe random shouldn't have to run 
# byacc when downloading the netl dist, as it is some what rare.  this is the
# rule for updateing the perl version of the parser.  it doesn't get run by
# default because of the above reasons.  unless you modify the the parser in
# an extremely anoying way, it shouldn't need updating anyway.
#
# the special byacc is available on CPAN somewhere under the /src directory,
# i believe.

face/perltk/face/Netl/Config/Parser.pm:config.y
	@echo warning: you need a specially patched version of byacc for this!
	$(CC) -C -DNETL_CONFIG_Y_PERL -E - < config.y > config.i 
	byacc -P - < config.i
	perl -e '<STDIN>;					\
		while(<STDIN>) {				\
			next if /^\;\# \d+ \"\"/;		\
			next if /^\*$$/;			\
			next if m!^/\*$$!;			\
			next if m!^\*/$$!;			\
			s/^\;\#//;				\
			print;					\
		}' < y.tab.pl > Parser.pm
	mv Parser.pm face/perltk/Netl/Config/Parser.pm
	$(RM) Parser.pm y.tab.pl config.i

parser:config.tab.o lex.yy.o

config.tab.o:config.tab.h config.tab.c
	$(CC) $(CFLAGS) -DNETL_CONFIG_Y_C -c config.tab.c -o config.tab.o

config.tab.h config.tab.c:config.y
	$(YACC) $(YACCFLAGS) config.y

#===============================================================================
# rpm stuff
#===============================================================================

rpm:dist
	cd face/perltk && perl Makefile.PL && make dist
	su -c  'cp -f $(DIST)-$(VER).tar.gz /usr/src/redhat/SOURCES &&	       \
		mv -f face/perltk/tknetl-$(VER).tar.gz /usr/src/redhat/SOURCES && \
		rpm -ba netl.spec &&					       \
		rpm -i /usr/src/redhat/RPMS/*/$(DIST)-$(VER)*.rpm &&	       \
		cd face/perltk &&					       \
		rpm -ba tknetl.spec &&					       \
		rpm -e netl'
	sh -c 'cp /usr/src/redhat/RPMS/*/{tk,}$(DIST)-$(VER)*.rpm .'
	sh -c 'cp /usr/src/redhat/SRPMS/{tk,}$(DIST)-$(VER)*.rpm .'

#===============================================================================
# install:
#===============================================================================

OWN=-g 0 -o 0

.PHONY: install
install:
	install -d $(LIBPATH)
	install -d $(LIBPATH)/sbin
	install $(OWN) -m 544 netl $(LIBPATH)/sbin
	install $(OWN) -m 555 hwpassive $(LIBPATH)/sbin
	install -d $(SUBINPATH)
	cd $(SUBINPATH);$(RM) netl hwpassive
	cd $(SUBINPATH);ln $(LIBPATH)/sbin/* . || cp $(LIBPATH)/sbin/* .
	install -d $(LIBPATH)/bin
	install $(OWN) -m 544 neta xd $(LIBPATH)/bin
	install $(OWN) -m 555 dcp.pl $(LIBPATH)/bin/dcp
	install $(OWN) -m 555 tdr.pl $(LIBPATH)/bin/tdr
	install $(OWN) -m 555 hwlookup $(LIBPATH)/bin
	install $(OWN) -m 555 netlcc.sh $(LIBPATH)/bin/netlcc
	install -d $(BINPATH)
	cd $(BINPATH);$(RM) neta xd dcp tdr hwlookup netlcc
	cd $(BINPATH);ln $(LIBPATH)/bin/* . || cp $(LIBPATH)/bin/* .
	install -d $(LIBPATH)/man/man1 $(LIBPATH)/man/man5 $(LIBPATH)/man/man8
	install $(OWN) -m 644 doc/*.1 $(LIBPATH)/man/man1
	install $(OWN) -m 644 doc/*.5 $(LIBPATH)/man/man5
	install $(OWN) -m 644 doc/*.8 $(LIBPATH)/man/man8
	install -d $(MANPATH) $(MANPATH)/man1 $(MANPATH)/man5 $(MANPATH)/man8
	cd $(MANPATH)/man1; ln -f $(LIBPATH)/man/man1/* . || cp $(LIBPATH)/man/man1 .
	cd $(MANPATH)/man5; ln -f $(LIBPATH)/man/man5/* . || cp $(LIBPATH)/man/man5 .
	cd $(MANPATH)/man8; ln -f $(LIBPATH)/man/man8/* . || cp $(LIBPATH)/man/man8 .
	$(RM) -r $(PREFIX)/lib/netl
	cd $(LIBPATH)/..; ln -s $(DIST)-$(VER) netl
	install -d $(LIBPATH)/dump
	install -d $(INCLUDEPATH)/netl
	install $(OWN) -m 644 include/netl/*.h $(INCLUDEPATH)/netl
	install $(OWN) -m 755 libnetl.so $(LIBPATH)
	install $(OWN) -m 644 hwcode $(LIBPATH)
	cd in; $(MAKE) install
	cd out; $(MAKE) install
	cd filt; $(MAKE) install

install.conf:
	install -d $(INST)/etc
	install $(OWN) -m 644 conf/netl.conf $(INST)/etc/netl.conf

web:dist
	mkdir ../public_html || true
	cd doc;$(MAKE)
	cp doc/*.html doc/*.gif HISTORY ../public_html
	cp $(DIST)-$(VER).tar.gz ../public_html
	cp ../dist/*.rpm ../public_html
	cp ../dist/netl-1.0*.tar.gz ../public_html
	cp -r ../dist/rh* ../public_html

#===============================================================================
# clean:
#===============================================================================

.PHONY: clean
clean:
	$(RM) netl netl.exe neta neta.exe xd xd.exe hwlookup hwlookup.exe
	$(RM) dcp dcp.exe
	$(RM) tmp.dat core a.out 
	$(RM) *.o *.html *.tar *.tmp
	$(RM) -r $(DIST)-$(VER) tdr-$(TDR_VER)
	$(RM) t/*.diff t/*.diffERR t/*.diffRET t/*.ao t/*.aERR t/*.aRET
	$(RM) t/tdr.log t/core
	$(RM) lib*.so* lib*.a tdr.log
	$(RM) lex.yy.c config.tab.h config.tab.c config.output config_test
	$(RM) lex.yy.c config2.tab.h config2.tab.c config2.output config_test
	$(RM) userfilter.c *.so README INSTALL conf/*.c conf/*.so conf/*.o
	$(RM) *.a *.so hwpassive hwpassive.exe configure.out *.exe
	$(RM) netlcc.sh netlcc dcp.pl
	$(RM) config2.y
	cd in; $(MAKE) clean
	cd filt; $(MAKE) clean
	cd out; $(MAKE) clean

distclean:clean

realclean:clean
	$(RM) *.tar.gz *.zip *.sig *.rpm
	$(RM) Makefile.dep */Makefile.dep include/netl/version.h
	$(RM) -r ../public_html
	cd face/perltk && perl Makefile.PL && $(MAKE) distclean
	cd doc; $(MAKE) clean

wc:
	wc -l *.{c,y,l,pl} include/netl/*.h {in,filt,out}/*.{c,h} |sort -n | tee .wc

Makefile.dep:
	$(PERL) makedepend.pl

Makefile.inc include/netl/version.h :
	./configure

include Makefile.dep
