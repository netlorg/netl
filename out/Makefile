#@(#)netl/neta Makefile (c) 1996, 1997 graham the ollis
#(c) 1999 Graham THE Ollis and CORE
#===============================================================================
# Makefile for netl output modules

include ../Makefile.inc

CFLAGS+=-I ../include

OUTPUT_MODULES=dl.so dump.so log.so null.so pipe.so

all:$(OUTPUT_MODULES)

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
	install -d $(LIBPATH)/out
	install $(OUTPUT_MODULES) $(LIBPATH)/out

#===============================================================================
# clean:
#===============================================================================

.PHONY: clean
clean:
	$(RM) *.o *.so

Makefile.dep:
	cd ..; $(PERL) makedepend.pl

include Makefile.dep
