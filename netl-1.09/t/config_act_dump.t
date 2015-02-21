#!/bin/sh

../netl -L.. -v- -r- --stdout	'dump tcp name=web dstport=80'
