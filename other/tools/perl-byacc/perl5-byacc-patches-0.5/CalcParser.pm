"@(#)yaccpar 1.8 (Berkeley) 01/20/91 (JAKE-P5BP-0.5 12/16/96)";
package CalcParser;
$NUMBER=257;
$YYERRCODE=256;
@yylhs = (                                               -1,
    0,    0,    0,    0,    0,    0,
);
@yylen = (                                                2,
    1,    3,    3,    3,    3,    3,
);
@yydefred = (                                             0,
    1,    0,    0,    0,    0,    0,    0,    0,    6,    0,
    0,    4,    5,
);
@yydgoto = (                                              3,
);
@yysindex = (                                           -40,
    0,  -40,  -27,  -38,  -40,  -40,  -40,  -40,    0,  -25,
  -25,    0,    0,
);
@yyrindex = (                                             0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    1,
    2,    0,    0,
);
@yygindex = (                                             6,
);
$YYTABLESIZE=217;
@yytable = (                                              2,
    2,    3,    9,    7,    5,    0,    6,    4,    8,    0,
   10,   11,   12,   13,    7,    5,    7,    6,    0,    8,
    0,    8,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    2,    3,    2,    3,    2,    3,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    1,
);
@yycheck = (                                             40,
    0,    0,   41,   42,   43,   -1,   45,    2,   47,   -1,
    5,    6,    7,    8,   42,   43,   42,   45,   -1,   47,
   -1,   47,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   41,   41,   43,   43,   45,   45,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  257,
);
$YYFINAL=3;
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
$YYMAXTOKEN=257;
#if YYDEBUG
@yyname = (
"end-of-file",'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','',"'('","')'","'*'","'+'",'',"'-'",'',"'/'",'','','','','','','','','','','','','','',
'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',"NUMBER",
);
@yyrule = (
"\$accept : expr",
"expr : NUMBER",
"expr : expr '+' expr",
"expr : expr '-' expr",
"expr : expr '*' expr",
"expr : expr '/' expr",
"expr : '(' expr ')'",
);
#endif
sub yyclearin { $_[0]->{'yychar'} = -1; }
sub yyerrok { $_[0]->{'yyerrflag'} = 0; }
sub new {
  my $p = {'yylex' => $_[1], 'yyerror' => $_[2], 'yydebug' => $_[3]};
  bless $p, $_[0];
}
sub YYERROR { ++$_[0]->{'yynerrs'}; $_[0]->yy_err_recover; }
sub yy_err_recover {
  my ($p) = @_;
  if ($p->{'yyerrflag'} < 3)
  {
    $p->{'yyerrflag'} = 3;
    while (1)
    {
      if (($p->{'yyn'} = $yysindex[$p->{'yyss'}->[$p->{'yyssp'}]]) && 
          ($p->{'yyn'} += $YYERRCODE) >= 0 && 
          $yycheck[$p->{'yyn'}] == $YYERRCODE)
      {
        warn("yydebug: state " . 
                     $p->{'yyss'}->[$p->{'yyssp'}] . 
                     ", error recovery shifting to state" . 
                     $yytable[$p->{'yyn'}] . "\n") 
                       if $p->{'yydebug'};
        $p->{'yyss'}->[++$p->{'yyssp'}] = 
          $p->{'yystate'} = $yytable[$p->{'yyn'}];
        $p->{'yyvs'}->[++$p->{'yyvsp'}] = $p->{'yylval'};
        next yyloop;
      }
      else
      {
        warn("yydebug: error recovery discarding state ".
              $p->{'yyss'}->[$p->{'yyssp'}]. "\n") 
                if $p->{'yydebug'};
        return(undef) if $p->{'yyssp'} <= 0;
        --$p->{'yyssp'};
        --$p->{'yyvsp'};
      }
    }
  }
  else
  {
    return (undef) if $p->{'yychar'} == 0;
    if ($p->{'yydebug'})
    {
      $p->{'yys'} = '';
      if ($p->{'yychar'} <= $YYMAXTOKEN) { $p->{'yys'} = 
        $yyname[$p->{'yychar'}]; }
      if (!$p->{'yys'}) { $p->{'yys'} = 'illegal-symbol'; }
      warn("yydebug: state " . $p->{'yystate'} . 
                   ", error recovery discards " . 
                   "token " . $p->{'yychar'} . "(" . 
                   $p->{'yys'} . ")\n");
    }
    $p->{'yychar'} = -1;
    next yyloop;
  }
0;
} # yy_err_recover

sub yyparse {
  my ($p, $s) = @_;
  if ($p->{'yys'} = $ENV{'YYDEBUG'})
  {
    $p->{'yydebug'} = int($1) if $p->{'yys'} =~ /^(\d)/;
  }

  $p->{'yynerrs'} = 0;
  $p->{'yyerrflag'} = 0;
  $p->{'yychar'} = (-1);

  $p->{'yyssp'} = 0;
  $p->{'yyvsp'} = 0;
  $p->{'yyss'}->[$p->{'yyssp'}] = $p->{'yystate'} = 0;

yyloop: while(1)
  {
    yyreduce: {
      last yyreduce if ($p->{'yyn'} = $yydefred[$p->{'yystate'}]);
      if ($p->{'yychar'} < 0)
      {
        if ((($p->{'yychar'}, $p->{'yylval'}) = 
            &{$p->{'yylex'}}($s)) < 0) { $p->{'yychar'} = 0; }
        if ($p->{'yydebug'})
        {
          $p->{'yys'} = '';
          if ($p->{'yychar'} <= $#yyname) 
             { $p->{'yys'} = $yyname[$p->{'yychar'}]; }
          if (!$p->{'yys'}) { $p->{'yys'} = 'illegal-symbol'; };
          warn("yydebug: state " . $p->{'yystate'} . 
                       ", reading " . $p->{'yychar'} . " (" . 
                       $p->{'yys'} . ")\n");
        }
      }
      if (($p->{'yyn'} = $yysindex[$p->{'yystate'}]) && 
          ($p->{'yyn'} += $p->{'yychar'}) >= 0 && 
          $yycheck[$p->{'yyn'}] == $p->{'yychar'})
      {
        warn("yydebug: state " . $p->{'yystate'} . 
                     ", shifting to state " .
              $yytable[$p->{'yyn'}] . "\n") if $p->{'yydebug'};
        $p->{'yyss'}->[++$p->{'yyssp'}] = $p->{'yystate'} = 
          $yytable[$p->{'yyn'}];
        $p->{'yyvs'}->[++$p->{'yyvsp'}] = $p->{'yylval'};
        $p->{'yychar'} = (-1);
        --$p->{'yyerrflag'} if $p->{'yyerrflag'} > 0;
        next yyloop;
      }
      if (($p->{'yyn'} = $yyrindex[$p->{'yystate'}]) && 
          ($p->{'yyn'} += $p->{'yychar'}) >= 0 &&
          $yycheck[$p->{'yyn'}] == $p->{'yychar'})
      {
        $p->{'yyn'} = $yytable[$p->{'yyn'}];
        last yyreduce;
      }
      if (! $p->{'yyerrflag'}) {
        &{$p->{'yyerror'}}('syntax error', $s);
        ++$p->{'yynerrs'};
      }
      return(undef) if $p->yy_err_recover;
    } # yyreduce
    warn("yydebug: state " . $p->{'yystate'} . 
                 ", reducing by rule " . 
                 $p->{'yyn'} . " (" . $yyrule[$p->{'yyn'}] . 
                 ")\n") if $p->{'yydebug'};
    $p->{'yym'} = $yylen[$p->{'yyn'}];
    $p->{'yyval'} = $p->{'yyvs'}->[$p->{'yyvsp'}+1-$p->{'yym'}];
if ($p->{'yyn'} == 1) {
{ $p->{'yyval'} = $p->{'yyvs'}->[$p->{'yyvsp'}-0]; }
}
if ($p->{'yyn'} == 2) {
{ $p->{'yyval'} = $p->{'yyvs'}->[$p->{'yyvsp'}-2] + $p->{'yyvs'}->[$p->{'yyvsp'}-0]; }
}
if ($p->{'yyn'} == 3) {
{ $p->{'yyval'} = $p->{'yyvs'}->[$p->{'yyvsp'}-2] - $p->{'yyvs'}->[$p->{'yyvsp'}-0]; }
}
if ($p->{'yyn'} == 4) {
{ $p->{'yyval'} = $p->{'yyvs'}->[$p->{'yyvsp'}-2] * $p->{'yyvs'}->[$p->{'yyvsp'}-0]; }
}
if ($p->{'yyn'} == 5) {
{ $p->{'yyval'} = $p->{'yyvs'}->[$p->{'yyvsp'}-2] / $p->{'yyvs'}->[$p->{'yyvsp'}-0]; }
}
if ($p->{'yyn'} == 6) {
{ $p->{'yyval'} = $p->{'yyvs'}->[$p->{'yyvsp'}-1]; }
}
    $p->{'yyssp'} -= $p->{'yym'};
    $p->{'yystate'} = $p->{'yyss'}->[$p->{'yyssp'}];
    $p->{'yyvsp'} -= $p->{'yym'};
    $p->{'yym'} = $yylhs[$p->{'yyn'}];
    if ($p->{'yystate'} == 0 && $p->{'yym'} == 0)
    {
      warn("yydebug: after reduction, shifting from state 0 ",
            "to state $YYFINAL\n") if $p->{'yydebug'};
      $p->{'yystate'} = $YYFINAL;
      $p->{'yyss'}->[++$p->{'yyssp'}] = $YYFINAL;
      $p->{'yyvs'}->[++$p->{'yyvsp'}] = $p->{'yyval'};
      if ($p->{'yychar'} < 0)
      {
        if ((($p->{'yychar'}, $p->{'yylval'}) = 
            &{$p->{'yylex'}}($s)) < 0) { $p->{'yychar'} = 0; }
        if ($p->{'yydebug'})
        {
          $p->{'yys'} = '';
          if ($p->{'yychar'} <= $#yyname) 
            { $p->{'yys'} = $yyname[$p->{'yychar'}]; }
          if (!$p->{'yys'}) { $p->{'yys'} = 'illegal-symbol'; }
          warn("yydebug: state $YYFINAL, reading " . 
               $p->{'yychar'} . " (" . $p->{'yys'} . ")\n");
        }
      }
      return ($p->{'yyvs'}->[1]) if $p->{'yychar'} == 0;
      next yyloop;
    }
    if (($p->{'yyn'} = $yygindex[$p->{'yym'}]) && 
        ($p->{'yyn'} += $p->{'yystate'}) >= 0 && 
        $p->{'yyn'} <= $#yycheck && 
        $yycheck[$p->{'yyn'}] == $p->{'yystate'})
    {
        $p->{'yystate'} = $yytable[$p->{'yyn'}];
    } else {
        $p->{'yystate'} = $yydgoto[$p->{'yym'}];
    }
    warn("yydebug: after reduction, shifting from state " . 
        $p->{'yyss'}->[$p->{'yyssp'}] . " to state " . 
        $p->{'yystate'} . "\n") if $p->{'yydebug'};
    $p->{'yyss'}[++$p->{'yyssp'}] = $p->{'yystate'};
    $p->{'yyvs'}[++$p->{'yyvsp'}] = $p->{'yyval'};
  } # yyloop
} # yyparse
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
