#!/bin/sh

../netl -r- -v- -z -L.. --input file 'log raw name=raw' <<EOF
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
eg/icmp.dg
eg/udp.dg
eg/tcp.dg
EOF

../netl -r- -v- -z -L.. --input file 'log raw name=from_fig srchw=00:40:95:d1:dc:1f' <<EOF
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
eg/icmp.dg
eg/udp.dg
eg/tcp.dg
EOF

../netl -r- -v- -z -L.. --input file 'log raw name=to_loop srchw=00:00:00:00:00:00' <<EOF
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
eg/icmp.dg
eg/udp.dg
eg/tcp.dg
EOF


