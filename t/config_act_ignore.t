#!/bin/sh

../netl -L.. -v- -r- --stdout	'ignore tcp name=web dstport=80'
