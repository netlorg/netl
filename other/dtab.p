#!/usr/bin/perl -w

for(<STDIN>) {
	while(s/^  //) { print "\t"; }
	print;
}
