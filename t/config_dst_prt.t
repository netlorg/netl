#!/bin/sh

../netl -L.. -v- -r- --stdout	'log udp dstport=47 name=oink47' \
				'log udp dstport=33434-60000 name=traceroute' \
				'log tcp dstport=80 name=web' \
				'log tcp dstport=200-300 name=tcp_range'
