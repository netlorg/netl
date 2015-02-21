#!/bin/sh

../netl -L.. -v- -r- --stdout	'alias starscream 10.10.10.4' \
				'alias figment    10.10.10.2' \
				'alias pacific    10.10.10.1'
