#!/bin/sh

../netl -r- -v- -z -L.. --input file 'log tcp name=syn flag=syn' <<EOF
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
EOF

../netl -r- -v- -z -L.. --input file 'log tcp name=www_connect dstport=80 flag=syn' <<EOF
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
EOF

../netl -r- -v- -z -L.. --input file	'log tcp name=client dstport=80' \
					'log tcp name=server srcport=80' \
					'log tcp name=error' <<EOF
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
EOF

../netl -v- -z -L.. --input file	'alias figment 10.10.10.2' \
					'alias starscream 10.10.10.4' \
					'log tcp name=client dstport=80' \
					'log tcp name=server srcport=80' \
					'log tcp name=error' <<EOF
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
EOF


