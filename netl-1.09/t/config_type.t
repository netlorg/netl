#!/bin/sh

../netl -L.. -v- -r- --stdout	'log icmp type=echo name=ping' \
				'log icmp type=echoreply name=pong'
