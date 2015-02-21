%{
package CalcParser;
%}

%token NUMBER
%left '+' '-'
%left '*' '/'

%%
expr:		NUMBER		{ $$ = $1; }
	|	expr '+' expr	{ $$ = $1 + $3; }
	|	expr '-' expr	{ $$ = $1 - $3; }
	|	expr '*' expr	{ $$ = $1 * $3; }
	|	expr '/' expr	{ $$ = $1 / $3; }
	|	'(' expr ')'	{ $$ = $2; }
	;
%%
# $Id: calc.y,v 1.7 1996/12/17 01:29:51 jake Exp $

sub yylex
{
    my ($s) = @_;
    my ($c, $val);

    while (($c = $s->getc) eq ' ' || $c eq "\t" || $c eq "\n") {
    }

    if ($c eq '') {
	return 0;
    }

    elsif ($c =~ /[0-9]/) {
	$val = $c;
	while (($c = $s->getc) =~ /[0-9]/) {
	    $val .= $c;
	}
	$s->ungetc;
	return ($NUMBER, $val);
    }

    else {
	return ord($c);
    }
}

sub yyerror {
    my ($msg, $s) = @_;
    die "$msg at " . $s->name . " line " . $s->lineno . ".\n";
}

1;
