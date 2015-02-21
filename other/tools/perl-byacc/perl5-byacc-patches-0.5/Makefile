# $Id: Makefile,v 1.4 1996/12/17 01:27:15 jake Exp $

CalcParser.pm: calc.y
	byacc -l -P calc.y
	mv y.tab.pl CalcParser.pm

clean:
	-rm -f CalcParser.pm
