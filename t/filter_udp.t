#!/bin/sh

../netl -r- -v- -z -L.. --input file	'log udp name=udp' <<EOF
eg/tcp.dg
eg/icmp.dg
eg/udp.dg
EOF

../netl -r- -v- -z -L.. --input file	'log udp name=udp dstport=47' <<EOF
eg/udp.dg
eg/tcp.dg
eg/icmp.dg
EOF

../netl -r- -v- -z -L.. --input file	'log udp name=udp dstport=81' <<EOF
eg/tcp.dg
eg/icmp.dg
eg/udp.dg
EOF

../netl -r- -v- -z -L.. --input file	'log udp name=udp srcport=1261' <<EOF
eg/udp.dg
eg/tcp.dg
eg/icmp.dg
EOF

../netl -r- -v- -z -L.. --input file	'log udp name=udp srcport=47' <<EOF
eg/tcp.dg
eg/udp.dg
eg/icmp.dg
EOF

