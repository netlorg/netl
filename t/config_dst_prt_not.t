#!/bin/sh

../netl -L.. -v- -r- --stdout	'log udp !dstport=47 name=oink47' \
				'log tcp !dstport=80 name=web'
