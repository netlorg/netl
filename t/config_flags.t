#!/bin/sh

../netl -L.. -v- -r- --stdout	'log tcp flag=syn !flag=all name=syn'
