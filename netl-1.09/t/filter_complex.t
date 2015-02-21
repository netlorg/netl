#!/bin/sh

../netl -v- -z -L.. --input file	'alias figment 10.10.10.2' \
					'alias starscream 10.10.10.4' \
					'log tcp name=syn flag=syn !flag=all' \
					'log tcp name=syn_ack flag=syn,ack !flag=all' \
					'log tcp name=fin_ack flag=fin,ack !flag=all' \
					'log tcp name=client dstport=80' \
					'log tcp name=server srcport=80' \
					'log udp name=udp' \
					'log icmp name=ping type=echo' \
					'log icmp name=pong type=echoreply' <<EOF
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
eg/ping/ping.dg
eg/ping/pong.dg
EOF
