#!/bin/sh

../netl -r- -v- -z -L.. --input file 'log icmp name=icmp' <<EOF
eg/ping/ping.dg
eg/ping/pong.dg
eg/udp.dg
eg/tcp.dg
EOF

../netl -r- -v- -z -L.. --input file 'log icmp name=ping type=echo' <<EOF
eg/udp.dg
eg/tcp.dg
eg/ping/ping.dg
eg/ping/pong.dg
EOF

../netl -r- -v- -z -L.. --input file 'log icmp name=pong type=echoreply' <<EOF
eg/udp.dg
eg/ping/ping.dg
eg/ping/pong.dg
eg/tcp.dg
EOF

../netl -r- -v- -z -L.. --input file	'log icmp name=ping type=echo' \
					'log icmp name=pong type=echoreply' <<EOF
eg/udp.dg
eg/tcp.dg
eg/ping/ping.dg
eg/ping/pong.dg
eg/udp.dg
eg/tcp.dg
EOF

../netl -v- -z -L.. --input file	'alias figment 10.10.10.2' \
					'alias starscream 10.10.10.4' \
					'log icmp name=ping type=echo' \
					'log icmp name=pong type=echoreply' <<EOF
eg/ping/ping.dg
eg/udp.dg
eg/tcp.dg
eg/ping/pong.dg
EOF

