# AntiSniff minimal Unix CLI version
#
# makefile for anti-sniff and various test components - based off of
# hobbit's netcat makefile, which in turn is based off of some ol'
# generic makefile.
#
### PREDEFINES

# DEFAULTS, possibly overridden by <systype> recursive call:
#debugging
#DFLAGS = -DDEBUG -Wall -g
DFLAGS = -Wall -g
CFLAGS = -O
XFLAGS = -D_linux_	# xtra cflags, set by systype targets
XLIBS =		# xtra libs if necessary?
STATIC =
CC = gcc $(CFLAGS)
#LD = $(CC) -s   # linker; defaults to stripped executables
LD = $(CC)   # linker; defaults to stripped executables
ENDIAN=-D_BIT_FIELDS_HTOL # big endian

BSD-ALL = bsd-anti_sniffer bsd-icmptimetest bsd-etherpingtest bsd-watchdnstest \
	bsd-arptest bsd-echotest
SOLARIS-ALL = solaris-anti_sniffer solaris-icmptimetest \
	solaris-etherpingtest solaris-watchdnstest solaris-arptest \
	solaris-echotest
LINUX-ALL = linux-anti_sniffer linux-icmptimetest linux-etherpingtest \
	linux-watchdnstest linux-arptest linux-echotest

#icmptime test
ICMPTIME_OBJS=main.o pingtime.o
SOL_ICMPTIME_OBJS=dlcommon.o dlpi_readwrite.o flood_net.o
BSD_ICMPTIME_OBJS=bpf_readwrite.o flood_net.o
LINUX_ICMPTIME_OBJS=linux_readwrite.o linux_flood_net.o

#etherping test
ETHERPING_OBJS=ethertest.o ip_util.o result_routines.o
SOL_ETHERPING_OBJS=dlpi_getetheraddr.o dlcommon.o dlpi_readwrite.o \
                   etherping.o flood_net.o
BSD_ETHERPING_OBJS=bpf_getetheraddr.o bpf_readwrite.o flood_net.o \
                   etherping.o
LINUX_ETHERPING_OBJS=linux_getetheraddr.o linux_readwrite.o linux_flood_net.o \
                     linux_etherping.o

#dns test
WATCHDNS_OBJS=watch_dns_test.o
SOL_WATCHDNS_OBJS=raw_watchdns.o dlpi_readwrite.o dlcommon.o
BSD_WATCHDNS_OBJS=bpf_watchdns.o bpf_readwrite.o
LINUX_WATCHDNS_OBJS=raw_watchdns.o linux_readwrite.o

#echo test
ECHOTEST_OBJS=test_echotest.o echotime.o

#arp test
ARPTEST_OBJS=test_arpreq.o result_routines.o ip_util.o arputils.o
SOL_ARPTEST_OBJS=dlpi_readwrite.o dlpi_watcharp.o dlpi_getetheraddr.o \
	dlcommon.o arpreqtest.o
BSD_ARPTEST_OBJS=bpf_readwrite.o bpf_watcharp.o bpf_getetheraddr.o arpreqtest.o
LINUX_ARPTEST_OBJS=linux_readwrite.o raw_watcharp.o linux_getetheraddr.o \
	linux_arpreqtest.o

#main anti-sniffer program objects
ANTISNIFF_OBJS=anti_sniff.o result_routines.o \
	run_etherpingtest.o run_icmptest.o \
	pingtime.o ip_util.o echotime.o run_echotest.o run_arptest.o \
	arputils.o
SOL_ANTISNIFF_OBJS=dlpi_readwrite.o dlcommon.o raw_watchdns.o \
	dlpi_getetheraddr.o dlpi_watcharp.o flood_net.o run_dnstest.o \
	arpreqtest.o etherping.o
BSD_ANTISNIFF_OBJS=bpf_readwrite.o bpf_watchdns.o bpf_getetheraddr.o \
	bpf_watcharp.o flood_net.o run_dnstest.o arpreqtest.o etherping.o
LINUX_ANTISNIFF_OBJS=linux_readwrite.o raw_watchdns.o linux_getetheraddr.o \
	raw_watcharp.o linux_flood_net.o linux_rundnstest.o \
	linux_arpreqtest.o linux_etherping.o

### BOGON-CATCHERS

bogus:
	@echo "choose one of the following :" 
	@echo " make OpenBSD-all,solaris2{5,6,7}-all,linux-all"
	@echo "       [master program and all test programs]"
	@echo ""
	@echo " make OpenBSD-anti_sniffer,solaris2{5,6,7}-anti_sniffer,"
	@echo "      linux-anti_sniffer"
	@echo "       [master program]"
	@echo ""
	@echo " make OpenBSD-icmptest,solaris2{5,6,7}-icmptimetest,linux-icmptimetest"
	@echo "       [time deltas on icmp traffic test]"
	@echo " make OpenBSD-etherpingtest,solaris2{5,6,7}-etherpingtest,linux-etherpingtest"
	@echo "       [ip address with bogus MAC test]"
	@echo " make OpenBSD-watchdnstest,solaris2{5,6,7}-watchdnstest,linux-watchdnstest"
	@echo "       [watch for DNS inverse queries test]"
	@echo " make OpenBSD-echotest,solaris2{5,6,7}-echotest,linux-echotest"
	@echo "       [time deltas on udp echo traffic test]"
	@echo " make OpenBSD-arptest,solaris2{5,6,7}-arptest,linux-arptest"
	@echo "       [tickle NT bogosity on ether filtering test]"
	@echo ""

### HARD TARGETS

####ALL####
OpenBSD-all :
	make -e $(BSD-ALL) $(MFLAGS) XFLAGS='-D_OpenBSD_ -D_BIT_FIELDS_LTOH' \
	XLIBS='-lkvm'

solaris25-all :
	make -e $(SOLARIS-ALL) $(MFLAGS) XFLAGS='-DSOLARIS -DSOLARIS25' \
	XLIBS='-lsocket -lnsl'

linux-all :
	make -e $(LINUX-ALL) $(MFLAGS) 

############

############
## ANTI_SNIFFER
OpenBSD-anti_sniffer :
	make -e bsd-anti_sniffer $(MFLAGS) \
	XFLAGS='-D_OpenBSD_ -D_BIT_FIELDS_LTOH' XLIBS='-lkvm'

# bsd anti_sniffer HARD TARGET
bsd-anti_sniffer :	$(ANTISNIFF_OBJS) $(BSD_ANTISNIFF_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) \
	$(STATIC) -o anti_sniffer $(ANTISNIFF_OBJS) $(BSD_ANTISNIFF_OBJS) \
	$(XLIBS)

solaris25-anti_sniffer :
	make -e solaris-anti_sniffer $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS25' XLIBS='-lsocket -lnsl'

solaris26-anti_sniffer :
	make -e solaris-anti_sniffer $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

solaris27-anti_sniffer :
	make -e solaris-anti_sniffer $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

# solaris anti_sniffer HARD TARGET
solaris-anti_sniffer :	$(ANTISNIFF_OBJS) $(SOL_ANTISNIFF_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o anti_sniffer $(ANTISNIFF_OBJS) \
	$(SOL_ANTISNIFF_OBJS) $(XLIBS)

linux-anti_sniffer :
	make -e linuxH-anti_sniffer $(MFLAGS) \
	XFLAGS='-D_linux_'

# linux anti_sniffer HARD TARGET
linuxH-anti_sniffer :	$(ANTISNIFF_OBJS) $(LINUX_ANTISNIFF_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o anti_sniffer $(ANTISNIFF_OBJS) \
	$(LINUX_ANTISNIFF_OBJS) $(XLIBS)

############

############
# ICMPTIMETEST
OpenBSD-icmptimetest :
	make -e bsd-icmptimetest $(MFLAGS) \
	XFLAGS='-D_OpenBSD_ -D_BIT_FIELDS_LTOH' XLIBS='-lkvm'

# bsd icmptimetest HARD TARGET
bsd-icmptimetest :	$(ICMPTIME_OBJS) $(BSD_ICMPTIME_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) \
	-o icmptimetest $(ICMPTIME_OBJS) $(BSD_ICMPTIME_OBJS) \
	$(XLIBS)

solaris25-icmptimetest :
	make -e solaris-icmptimetest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS25' XLIBS='-lsocket -lnsl'

solaris26-icmptimetest :
	make -e solaris-icmptimetest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

solaris27-icmptimetest :
	make -e solaris-icmptimetest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

# solaris-icmptimetest HARD TARGET
solaris-icmptimetest :	$(ICMPTIME_OBJS) $(SOL_ICMPTIME_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o icmptimetest $(ICMPTIME_OBJS) \
	$(SOL_ICMPTIME_OBJS) $(XLIBS)

linux-icmptimetest :
	make -e linuxH-icmptimetest $(MFLAGS) \
	XFLAGS='-D_linux_'

# linux HARD TARGET
linuxH-icmptimetest :	$(ICMPTIME_OBJS) $(LINUX_ICMPTIME_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o icmptimetest $(ICMPTIME_OBJS) \
	$(LINUX_ICMPTIME_OBJS) $(XLIBS)

############

############
# ETHERPINGTEST 
OpenBSD-etherpingtest :
	make -e bsd-etherpingtest $(MFLAGS) \
	XFLAGS='-D_OpenBSD_ -D_BIT_FIELDS_LTOH' XLIBS='-lkvm'

# bsd etherpingtest HARD TARGET
bsd-etherpingtest :	$(ETHERPING_OBJS) $(BSD_ETHERPING_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) -o etherpingtest \
	$(ETHERPING_OBJS) $(BSD_ETHERPING_OBJS) $(XLIBS)

solaris25-etherpingtest :
	make -e solaris-etherpingtest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS25' XLIBS='-lsocket -lnsl'

solaris26-etherpingtest :
	make -e solaris-etherpingtest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

solaris27-etherpingtest :
	make -e solaris-etherpingtest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

# solaris-etherpingtest HARD TARGET
solaris-etherpingtest : $(ETHERPING_OBJS) $(SOL_ETHERPING_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o etherpingtest $(ETHERPING_OBJS) \
	$(SOL_ETHERPING_OBJS) $(XLIBS)

linux-etherpingtest :
	make -e linuxH-etherpingtest $(MFLAGS) \
	XFLAGS='-D_linux_' 

# linux HARD TARGET
linuxH-etherpingtest :	$(ETHERPING_OBJS) $(LINUX_ETHERPING_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o etherpingtest $(ETHERPING_OBJS) \
	$(LINUX_ETHERPING_OBJS) $(XLIBS)

############

############
## WATCHDNSTEST
#watchdnstest : $(WATCHDNS_OBJS)
#	$(CC) $(CFLAGS) -o watchdnstest $(WATCHDNS_OBJS) $(DEFINES) $(LIBS)

OpenBSD-watchdnstest :
	make -e bsd-watchdnstest $(MFLAGS) \
	XFLAGS='-D_OpenBSD_ -D_BIT_FIELDS_LTOH' XLIBS='-lkvm'

# bsd watchdnstest HARD TARGET
bsd-watchdnstest :	$(WATCHDNS_OBJS) $(BSD_WATCHDNS_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) -o watchdnstest \
	$(WATCHDNS_OBJS) $(BSD_WATCHDNS_OBJS) $(XLIBS)

solaris25-watchdnstest :
	make -e solaris-watchdnstest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS25' XLIBS='-lsocket -lnsl'

solaris26-watchdnstest :
	make -e solaris-watchdnstest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

solaris27-watchdnstest :
	make -e solaris-watchdnstest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

# solaris watchdnstest HARD TARGET
solaris-watchdnstest : $(WATCHDNS_OBJS) $(SOL_WATCHDNS_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) -o watchdnstest $(WATCHDNS_OBJS) \
	$(SOL_WATCHDNS_OBJS) $(XLIBS)

linux-watchdnstest :
	make -e linuxH-watchdnstest $(MFLAGS) \
	XFLAGS='-D_linux_'

# linux watchdnstest HARD TARGET
linuxH-watchdnstest :	$(WATCHDNS_OBJS) $(LINUX_WATCHDNS_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) -o watchdnstest $(WATCHDNS_OBJS) \
	$(LINUX_WATCHDNS_OBJS) $(XLIBS)

############

############
## ECHOTEST
#echotest :	$(ECHOTEST_OBJS)
#	$(CC) $(CFLAGS) -o echotest $(ECHOTEST_OBJS) $(DEFINES) $(LIBS)

OpenBSD-echotest :
	make -e bsd-echotest $(MFLAGS) \
	XFLAGS='-D_OpenBSD_ -D_BIT_FIELDS_LTOH' XLIBS='-lkvm'

# bsd echotest HARD TARGET
bsd-echotest :	$(ECHOTEST_OBJS) $(BSD_ECHOTEST_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o echotest \
	$(ECHOTEST_OBJS) $(BSD_ECHOTEST_OBJS) $(XLIBS)

solaris25-echotest :
	make -e solaris-echotest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS25' XLIBS='-lsocket -lnsl'

solaris26-echotest :
	make -e solaris-echotest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

solaris27-echotest :
	make -e solaris-echotest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

# solaris echotest HARD TARGET
solaris-echotest : $(ECHOTEST_OBJS) $(SOL_ECHOTEST_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o echotest $(ECHOTEST_OBJS) \
	$(SOL_ECHOTEST_OBJS) $(XLIBS)

linux-echotest :
	make -e linuxH-echotest $(MFLAGS) \
	XFLAGS='-D_linux_'

# linux echotest HARD TARGET
linuxH-echotest : $(ECHOTEST_OBJS) $(LINUX_ECHOTEST_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o echotest $(ECHOTEST_OBJS) \
	$(LINUX_ECHOTEST_OBJS) $(XLIBS)

############

############
## ARPTEST
OpenBSD-arptest :
	make -e bsd-arptest $(MFLAGS) \
	XFLAGS='-D_OpenBSD_ -D_BIT_FIELDS_LTOH' XLIBS='-lkvm'

bsd-arptest :	$(ARPTEST_OBJS) $(BSD_ARPTEST_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o arptest $(ARPTEST_OBJS) \
	$(BSD_ARPTEST_OBJS) $(XLIBS)

solaris25-arptest :
	make -e solaris-arptest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS25' XLIBS='-lsocket -lnsl'

solaris26-arptest :
	make -e solaris-arptest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

solaris27-arptest :
	make -e solaris-arptest $(MFLAGS) \
	XFLAGS='-DSOLARIS -DSOLARIS26' XLIBS='-lsocket -lnsl'

# solaris arptest HARD TARGET
solaris-arptest :	$(ARPTEST_OBJS) $(SOL_ARPTEST_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o arptest $(ARPTEST_OBJS) \
	$(SOL_ARPTEST_OBJS) $(XLIBS) 

linux-arptest :
	make -e linuxH-arptest $(MFLAGS) \
	XFLAGS='-D_linux_'

# linux arptest HARD TARGET
linuxH-arptest :	$(ARPTEST_OBJS) $(LINUX_ARPTEST_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) -o arptest $(ARPTEST_OBJS) \
	$(LINUX_ARPTEST_OBJS) $(XLIBS)

############

###
### FILES
anti_sniff.o :	anti_sniff.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c anti_sniff.c

result_routines.o :	result_routines.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c result_routines.c

run_dnstest.o :	run_dnstest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c run_dnstest.c

linux_rundnstest.o : linux_rundnstest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c linux_rundnstest.c

run_etherpingtest.o :	run_etherpingtest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c run_etherpingtest.c

run_icmptest.o :	run_icmptest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c run_icmptest.c

run_echotest.o :	run_echotest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c run_echotest.c

main.o :	main.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c main.c 

dlcommon.o :	dlcommon.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c dlcommon.c

dlpi_readwrite.o :       dlpi_readwrite.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c dlpi_readwrite.c

bpf_readwrite.o :	bpf_readwrite.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c bpf_readwrite.c

bpf_getetheraddr.o :	bpf_getetheraddr.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c bpf_getetheraddr.c

dlpi_getetheraddr.o :	dlpi_getetheraddr.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c dlpi_getetheraddr.c

linux_getetheraddr.o :	linux_getetheraddr.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c linux_getetheraddr.c

linux_readwrite.o :	linux_readwrite.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c linux_readwrite.c

pingtime.o :	pingtime.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c pingtime.c

flood_net.o :	flood_net.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c flood_net.c

linux_flood_net.o :	linux_flood_net.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c linux_flood_net.c

ethertest.o :	ethertest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c ethertest.c

test_echotest.o :	test_echotest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c test_echotest.c

echotime.o :	echotime.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c echotime.c

etherping.o :	etherping.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c etherping.c

linux_etherping.o :	linux_etherping.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c linux_etherping.c

raw_watchdns.o :	raw_watchdns.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c raw_watchdns.c

raw_watcharp.o :	raw_watcharp.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c raw_watcharp.c

dlpi_watcharp.o :	dlpi_watcharp.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c dlpi_watcharp.c

bpf_watchdns.o :	bpf_watchdns.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c bpf_watchdns.c

bpf_watcharp.o :	bpf_watcharp.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c bpf_watcharp.c

ip_util.o :	ip_util.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c ip_util.c

watch_dns_test.o :	watch_dns_test.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c watch_dns_test.c

test_arpreq.o :	test_arpreq.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c test_arpreq.c

arpreqtest.o :	arpreqtest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c arpreqtest.c

linux_arpreqtest.o : linux_arpreqtest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c linux_arpreqtest.c

arputils.o :	arputils.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c arputils.c

run_arptest.o :	run_arptest.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c run_arptest.c

clean:
	rm -f *.o anti_sniffer icmptimetest etherpingtest watchdnstest \
	echotest arptest core *.core 

