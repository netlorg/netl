#!/bin/sh

../netl -L.. -v- -r- --stdout	'log tcp name=web dstport=80'
