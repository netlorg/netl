#!/bin/sh

../netl -L.. -v- -r- --stdout	'log udp !srcport=47 name=oink47' \
				'log tcp !srcport=80 name=web'
