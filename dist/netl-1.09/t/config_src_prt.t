#!/bin/sh

../netl -L.. -v- -r- --stdout	'log udp srcport=47 name=oink47' \
				'log udp srcport=33434-60000 name=traceroute' \
				'log tcp srcport=80 name=web' \
				'log tcp srcport=200-300 name=tcp_range'
