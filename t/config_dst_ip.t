#!/bin/sh

../netl -L.. -v- -r- --stdout	'alias starscream 10.10.10.4' \
				'alias reliant 10.10.10.5' \
				'log udp dstip=starscream name=udp_star' \
				'log udp dstip=10.10.10.2 name=udp_fig' \
				'log tcp dstip=reliant name=tcp_reliant' \
				'log tcp dstip=10.10.10.1 name=tcp_pac'
