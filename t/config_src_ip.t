#!/bin/sh

../netl -L.. -v- -r- --stdout	'alias starscream 10.10.10.4' \
				'alias reliant 10.10.10.5' \
				'log udp srcip=starscream name=udp_star' \
				'log udp srcip=10.10.10.2 name=udp_fig' \
				'log tcp srcip=reliant name=tcp_reliant' \
				'log tcp srcip=10.10.10.1 name=tcp_pac'
