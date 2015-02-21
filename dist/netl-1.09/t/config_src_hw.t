#!/bin/sh

../netl -L.. -v- -r- --stdout	'log raw srchw=aa:bb:cc:dd:ee:ff name=hex' \
				'log raw !srchw=00:11:22:33:44:55 name=dec'
