#@(#)netl/neta Makefile (c) 1996, 1997 graham the ollis
#(c) 1999 Graham THE Ollis and CORE
#===============================================================================
# Makefile for netl input modules

include ../Makefile.inc

CFLAGS+=-I ../include

DEFAULT=linux-ether.so
INPUT_MODULES=linux-ether.so file.so pcap.so

all:$(INPUT_MODULES) default.so

default.so:linux-ether.so
	$(LN) -s linux-ether.so default.so

#===============================================================================
# object files:
#===============================================================================

%.so:%.o
	$(CC) -shared $(LDFLAGS) $(CFLAGS) -o $@ $<

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

#===============================================================================
# install:
#===============================================================================

.PHONY: install
install:
	install -d $(LIBPATH)/in
	install $(INPUT_MODULES) $(LIBPATH)/in
	cd $(LIBPATH)/in;$(RM) default.so;$(LN) -s $(DEFAULT) default.so

#===============================================================================
# clean:
#===============================================================================

.PHONY: clean
clean:
	$(RM) *.o *.so

Makefile.dep:
	cd ..; $(PERL) makedepend.pl
	

include Makefile.dep
