#@(#)netl/neta Makefile (c) 1996, 1997 graham the ollis
#(c) 1999 Graham THE Ollis and CORE
#===============================================================================
# Makefile for netl input modules

include ../Makefile.inc

CFLAGS+=-I ../include

FILT_MODULES=\
icmp4.so icmp6.so icmp.so \
ip4.so ip6.so ip.so \
tcp4.so tcp6.so tcp.so \
udp4.so udp6.so udp.so \
ignp.so \
raw.so \
dcp.so ping.so gnr.so

all:$(FILT_MODULES)

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
	install -d $(LIBPATH)/filt
	install $(FILT_MODULES) $(LIBPATH)/filt

#===============================================================================
# clean:
#===============================================================================

.PHONY: clean
clean:
	$(RM) *.o *.so
