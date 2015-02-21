#!/bin/sh

../netl -L.. -v- -r- --stdout	'log icmp code=1 name=one' \
				'log icmp code=2 name=two'
