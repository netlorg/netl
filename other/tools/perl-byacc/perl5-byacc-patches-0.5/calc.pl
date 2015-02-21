#!/usr/bin/perl

# $Id: calc.pl,v 1.2 1996/12/17 01:33:48 jake Exp $

# Really trivial calculator. Reads one expression from STDIN and
# evaluates it. Don't forget to hit ^D.

use CalcParser;
use Fstream;

$s = Fstream->new(\*STDIN, 'STDIN');
$p = CalcParser->new(\&CalcParser::yylex, \&CalcParser::yyerror, 0);

print $p->yyparse($s) . "\n";
