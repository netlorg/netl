#!/bin/sh

../netl -r- -v- -z -L.. --input file	'ignore ip name=ip' <<EOF
eg/icmp.dg
eg/tcp.dg
eg/udp.dg
eg/web/00.dg
eg/web/01.dg
eg/web/02.dg
eg/web/03.dg
eg/web/04.dg
eg/web/05.dg
eg/web/06.dg
eg/web/07.dg
eg/web/08.dg
eg/web/09.dg
eg/web/10.dg
EOF

../netl -r- -v- -z -L.. --input file	'ignore icmp name=icmp' \
					'ignore udp name=udp' \
					'ignore tcp name=tcp' \
					'ignore ip name=error' <<EOF
eg/icmp.dg
eg/tcp.dg
eg/udp.dg
eg/web/00.dg
eg/web/01.dg
eg/web/02.dg
eg/web/03.dg
eg/web/04.dg
eg/web/05.dg
eg/web/06.dg
eg/web/07.dg
eg/web/08.dg
eg/web/09.dg
eg/web/10.dg
EOF

../netl -r- -v- -z -L.. --input file	'ignore ip name=ip srcip=10.10.10.2' <<EOF
eg/icmp.dg
eg/tcp.dg
eg/udp.dg
eg/web/00.dg
eg/web/01.dg
eg/web/02.dg
eg/web/03.dg
eg/web/04.dg
eg/web/05.dg
eg/web/06.dg
eg/web/07.dg
eg/web/08.dg
eg/web/09.dg
eg/web/10.dg
EOF

../netl -r- -v- -z -L.. --input file	'ignore ip name=ip dstip=128.196.137.17' <<EOF
eg/icmp.dg
eg/tcp.dg
eg/udp.dg
eg/web/00.dg
eg/web/01.dg
eg/web/02.dg
eg/web/03.dg
eg/web/04.dg
eg/web/05.dg
eg/web/06.dg
eg/web/07.dg
eg/web/08.dg
eg/web/09.dg
eg/web/10.dg
EOF


