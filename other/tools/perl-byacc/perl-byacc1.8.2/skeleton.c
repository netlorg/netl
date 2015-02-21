/* $Id: skeleton.c,v 1.3 1996/12/17 01:39:00 jake Exp $ */
/* Modified for perl5-byacc-patches-0.5 */

#include "defs.h"

/*  The banner used here should be replaced with an #ident directive    */
/*  if the target C compiler supports #ident directives.                */
/*                                                                      */
/*  If the skeleton is changed, the banner should be changed so that    */
/*  the altered version can easily be distinguished from the original.  */

static char *c_banner[] =
{
    "#ifndef lint",
    "static char yysccsid[] = \"@(#)yaccpar 1.8 (Berkeley) 01/20/91\";",
    "#endif",
    "#define YYBYACC 1",
    (char *) NULL
};

static char *perl_banner[] =
{
    "\"@(#)yaccpar 1.8 (Berkeley) 01/20/91 (JAKE-P5BP-0.5 12/16/96)\";",
    (char *) NULL
};
  
char **banner[] = { c_banner, perl_banner };

static char *c_tables[] =
{
    "extern short yylhs[];",
    "extern short yylen[];",
    "extern short yydefred[];",
    "extern short yydgoto[];",
    "extern short yysindex[];",
    "extern short yyrindex[];",
    "extern short yygindex[];",
    "extern short yytable[];",
    "extern short yycheck[];",
    "#if YYDEBUG",
    "extern char *yyname[];",
    "extern char *yyrule[];",
    "#endif",
    (char *) NULL
};

char **tables[] = { c_tables, (char **) NULL };

static char *c_header[] =
{
    "#define yyclearin (yychar=(-1))",
    "#define yyerrok (yyerrflag=0)",
    "#ifdef YYSTACKSIZE",
    "#ifndef YYMAXDEPTH",
    "#define YYMAXDEPTH YYSTACKSIZE",
    "#endif",
    "#else",
    "#ifdef YYMAXDEPTH",
    "#define YYSTACKSIZE YYMAXDEPTH",
    "#else",
    "#define YYSTACKSIZE 500",
    "#define YYMAXDEPTH 500",
    "#endif",
    "#endif",
    "int yydebug;",
    "int yynerrs;",
    "int yyerrflag;",
    "int yychar;",
    "short *yyssp;",
    "YYSTYPE *yyvsp;",
    "YYSTYPE yyval;",
    "YYSTYPE yylval;",
    "short yyss[YYSTACKSIZE];",
    "YYSTYPE yyvs[YYSTACKSIZE];",
    "#define yystacksize YYSTACKSIZE",
    (char *) NULL
};

static char *perl_header[] =
{
    "sub yyclearin { $_[0]->{'yychar'} = -1; }",
    "sub yyerrok { $_[0]->{'yyerrflag'} = 0; }",
    (char *) NULL
};

char **header[] = { c_header, perl_header };

static char *c_body[] =
{
    "#define YYABORT goto yyabort",
    "#define YYACCEPT goto yyaccept",
    "#define YYERROR goto yyerrlab",
    "int",
    "yyparse()",
    "{",
    "    register int yym, yyn, yystate;",
    "#if YYDEBUG",
    "    register char *yys;",
    "    extern char *getenv();",
    "",
    "    if (yys = getenv(\"YYDEBUG\"))",
    "    {",
    "        yyn = *yys;",
    "        if (yyn >= '0' && yyn <= '9')",
    "            yydebug = yyn - '0';",
    "    }",
    "#endif",
    "",
    "    yynerrs = 0;",
    "    yyerrflag = 0;",
    "    yychar = (-1);",
    "",
    "    yyssp = yyss;",
    "    yyvsp = yyvs;",
    "    *yyssp = yystate = 0;",
    "",
    "yyloop:",
    "    if (yyn = yydefred[yystate]) goto yyreduce;",
    "    if (yychar < 0)",
    "    {",
    "        if ((yychar = yylex()) < 0) yychar = 0;",
    "#if YYDEBUG",
    "        if (yydebug)",
    "        {",
    "            yys = 0;",
    "            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];",
    "            if (!yys) yys = \"illegal-symbol\";",
    "            printf(\"yydebug: state %d, reading %d (%s)\\n\", yystate,",
    "                    yychar, yys);",
    "        }",
    "#endif",
    "    }",
    "    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&",
    "            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)",
    "    {",
    "#if YYDEBUG",
    "        if (yydebug)",
    "            printf(\"yydebug: state %d, shifting to state %d\\n\",",
    "                    yystate, yytable[yyn]);",
    "#endif",
    "        if (yyssp >= yyss + yystacksize - 1)",
    "        {",
    "            goto yyoverflow;",
    "        }",
    "        *++yyssp = yystate = yytable[yyn];",
    "        *++yyvsp = yylval;",
    "        yychar = (-1);",
    "        if (yyerrflag > 0)  --yyerrflag;",
    "        goto yyloop;",
    "    }",
    "    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&",
    "            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)",
    "    {",
    "        yyn = yytable[yyn];",
    "        goto yyreduce;",
    "    }",
    "    if (yyerrflag) goto yyinrecovery;",
    "#ifdef lint",
    "    goto yynewerror;",
    "#endif",
    "yynewerror:",
    "    yyerror(\"syntax error\");",
    "#ifdef lint",
    "    goto yyerrlab;",
    "#endif",
    "yyerrlab:",
    "    ++yynerrs;",
    "yyinrecovery:",
    "    if (yyerrflag < 3)",
    "    {",
    "        yyerrflag = 3;",
    "        for (;;)",
    "        {",
    "            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&",
    "                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)",
    "            {",
    "#if YYDEBUG",
    "                if (yydebug)",
    "                    printf(\"yydebug: state %d, error recovery shifting\\",
    " to state %d\\n\", *yyssp, yytable[yyn]);",
    "#endif",
    "                if (yyssp >= yyss + yystacksize - 1)",
    "                {",
    "                    goto yyoverflow;",
    "                }",
    "                *++yyssp = yystate = yytable[yyn];",
    "                *++yyvsp = yylval;",
    "                goto yyloop;",
    "            }",
    "            else",
    "            {",
    "#if YYDEBUG",
    "                if (yydebug)",
    "                    printf(\"yydebug: error recovery discarding state %d\
\\n\",",
    "                            *yyssp);",
    "#endif",
    "                if (yyssp <= yyss) goto yyabort;",
    "                --yyssp;",
    "                --yyvsp;",
    "            }",
    "        }",
    "    }",
    "    else",
    "    {",
    "        if (yychar == 0) goto yyabort;",
    "#if YYDEBUG",
    "        if (yydebug)",
    "        {",
    "            yys = 0;",
    "            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];",
    "            if (!yys) yys = \"illegal-symbol\";",
    "            printf(\"yydebug: state %d, error recovery discards token %d\
 (%s)\\n\",",
    "                    yystate, yychar, yys);",
    "        }",
    "#endif",
    "        yychar = (-1);",
    "        goto yyloop;",
    "    }",
    "yyreduce:",
    "#if YYDEBUG",
    "    if (yydebug)",
    "        printf(\"yydebug: state %d, reducing by rule %d (%s)\\n\",",
    "                yystate, yyn, yyrule[yyn]);",
    "#endif",
    "    yym = yylen[yyn];",
    "    yyval = yyvsp[1-yym];",
    "    switch (yyn)",
    "    {",
    (char *) NULL
};

static char *perl_body[] =
{
    "sub new {",
    "  my $p = {'yylex' => $_[1], 'yyerror' => $_[2], 'yydebug' => $_[3]};",
    "  bless $p, $_[0];",
    "}",
    "sub YYERROR { ++$_[0]->{'yynerrs'}; $_[0]->yy_err_recover; }",
    "sub yy_err_recover {",
    "  my ($p) = @_;",
    "  if ($p->{'yyerrflag'} < 3)",
    "  {",
    "    $p->{'yyerrflag'} = 3;",
    "    while (1)",
    "    {",
    "      if (($p->{'yyn'} = $yysindex[$p->{'yyss'}->[$p->{'yyssp'}]]) && ",
    "          ($p->{'yyn'} += $YYERRCODE) >= 0 && ",
    "          $yycheck[$p->{'yyn'}] == $YYERRCODE)",
    "      {",
    "        warn(\"yydebug: state \" . ",
    "                     $p->{'yyss'}->[$p->{'yyssp'}] . ",
    "                     \", error recovery shifting to state\" . ",
    "                     $yytable[$p->{'yyn'}] . \"\\n\") ",
    "                       if $p->{'yydebug'};",
    "        $p->{'yyss'}->[++$p->{'yyssp'}] = ",
    "          $p->{'yystate'} = $yytable[$p->{'yyn'}];",
    "        $p->{'yyvs'}->[++$p->{'yyvsp'}] = $p->{'yylval'};",
    "        next yyloop;",
    "      }",
    "      else",
    "      {",
    "        warn(\"yydebug: error recovery discarding state \".",
    "              $p->{'yyss'}->[$p->{'yyssp'}]. \"\\n\") ",
    "                if $p->{'yydebug'};",
    "        return(undef) if $p->{'yyssp'} <= 0;",
    "        --$p->{'yyssp'};",
    "        --$p->{'yyvsp'};",
    "      }",
    "    }",
    "  }",
    "  else",
    "  {",
    "    return (undef) if $p->{'yychar'} == 0;",
    "    if ($p->{'yydebug'})",
    "    {",
    "      $p->{'yys'} = '';",
    "      if ($p->{'yychar'} <= $YYMAXTOKEN) { $p->{'yys'} = ",
    "        $yyname[$p->{'yychar'}]; }",
    "      if (!$p->{'yys'}) { $p->{'yys'} = 'illegal-symbol'; }",
    "      warn(\"yydebug: state \" . $p->{'yystate'} . ",
    "                   \", error recovery discards \" . ",
    "                   \"token \" . $p->{'yychar'} . \"(\" . ",
    "                   $p->{'yys'} . \")\\n\");",
    "    }",
    "    $p->{'yychar'} = -1;",
    "    next yyloop;",
    "  }",
    "0;",
    "} # yy_err_recover",
    "",
    "sub yyparse {",
    "  my ($p, $s) = @_;",
    "  if ($p->{'yys'} = $ENV{'YYDEBUG'})",
    "  {",
    "    $p->{'yydebug'} = int($1) if $p->{'yys'} =~ /^(\\d)/;",
    "  }",
    "",
    "  $p->{'yynerrs'} = 0;",
    "  $p->{'yyerrflag'} = 0;",
    "  $p->{'yychar'} = (-1);",
    "",
    "  $p->{'yyssp'} = 0;",
    "  $p->{'yyvsp'} = 0;",
    "  $p->{'yyss'}->[$p->{'yyssp'}] = $p->{'yystate'} = 0;",
    "",
    "yyloop: while(1)",
    "  {",
    "    yyreduce: {",
    "      last yyreduce if ($p->{'yyn'} = $yydefred[$p->{'yystate'}]);",
    "      if ($p->{'yychar'} < 0)",
    "      {",
    "        if ((($p->{'yychar'}, $p->{'yylval'}) = ",
    "            &{$p->{'yylex'}}($s)) < 0) { $p->{'yychar'} = 0; }",
    "        if ($p->{'yydebug'})",
    "        {",
    "          $p->{'yys'} = '';",
    "          if ($p->{'yychar'} <= $#yyname) ",
    "             { $p->{'yys'} = $yyname[$p->{'yychar'}]; }",
    "          if (!$p->{'yys'}) { $p->{'yys'} = 'illegal-symbol'; };",
    "          warn(\"yydebug: state \" . $p->{'yystate'} . ",
    "                       \", reading \" . $p->{'yychar'} . \" (\" . ",
    "                       $p->{'yys'} . \")\\n\");",
    "        }",
    "      }",
    "      if (($p->{'yyn'} = $yysindex[$p->{'yystate'}]) && ",
    "          ($p->{'yyn'} += $p->{'yychar'}) >= 0 && ",
    "          $yycheck[$p->{'yyn'}] == $p->{'yychar'})",
    "      {",
    "        warn(\"yydebug: state \" . $p->{'yystate'} . ",
    "                     \", shifting to state \" .",
    "              $yytable[$p->{'yyn'}] . \"\\n\") if $p->{'yydebug'};",
    "        $p->{'yyss'}->[++$p->{'yyssp'}] = $p->{'yystate'} = ",
    "          $yytable[$p->{'yyn'}];",
    "        $p->{'yyvs'}->[++$p->{'yyvsp'}] = $p->{'yylval'};",
    "        $p->{'yychar'} = (-1);",
    "        --$p->{'yyerrflag'} if $p->{'yyerrflag'} > 0;",
    "        next yyloop;",
    "      }",
    "      if (($p->{'yyn'} = $yyrindex[$p->{'yystate'}]) && ",
    "          ($p->{'yyn'} += $p->{'yychar'}) >= 0 &&",
    "          $yycheck[$p->{'yyn'}] == $p->{'yychar'})",
    "      {",
    "        $p->{'yyn'} = $yytable[$p->{'yyn'}];",
    "        last yyreduce;",
    "      }",
    "      if (! $p->{'yyerrflag'}) {",
    "        &{$p->{'yyerror'}}('syntax error', $s);",
    "        ++$p->{'yynerrs'};",
    "      }",
    "      return(undef) if $p->yy_err_recover;",
    "    } # yyreduce",
    "    warn(\"yydebug: state \" . $p->{'yystate'} . ",
    "                 \", reducing by rule \" . ",
    "                 $p->{'yyn'} . \" (\" . $yyrule[$p->{'yyn'}] . ",
    "                 \")\\n\") if $p->{'yydebug'};",
    "    $p->{'yym'} = $yylen[$p->{'yyn'}];",
    "    $p->{'yyval'} = $p->{'yyvs'}->[$p->{'yyvsp'}+1-$p->{'yym'}];",
    (char *) NULL
};

char **body[] = { c_body, perl_body };

static char *c_trailer[] =
{
    "    }",
    "    yyssp -= yym;",
    "    yystate = *yyssp;",
    "    yyvsp -= yym;",
    "    yym = yylhs[yyn];",
    "    if (yystate == 0 && yym == 0)",
    "    {",
    "#if YYDEBUG",
    "        if (yydebug)",
    "            printf(\"yydebug: after reduction, shifting from state 0 to\\",
    " state %d\\n\", YYFINAL);",
    "#endif",
    "        yystate = YYFINAL;",
    "        *++yyssp = YYFINAL;",
    "        *++yyvsp = yyval;",
    "        if (yychar < 0)",
    "        {",
    "            if ((yychar = yylex()) < 0) yychar = 0;",
    "#if YYDEBUG",
    "            if (yydebug)",
    "            {",
    "                yys = 0;",
    "                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];",
    "                if (!yys) yys = \"illegal-symbol\";",
    "                printf(\"yydebug: state %d, reading %d (%s)\\n\",",
    "                        YYFINAL, yychar, yys);",
    "            }",
    "#endif",
    "        }",
    "        if (yychar == 0) goto yyaccept;",
    "        goto yyloop;",
    "    }",
    "    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&",
    "            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)",
    "        yystate = yytable[yyn];",
    "    else",
    "        yystate = yydgoto[yym];",
    "#if YYDEBUG",
    "    if (yydebug)",
    "        printf(\"yydebug: after reduction, shifting from state %d \\",
    "to state %d\\n\", *yyssp, yystate);",
    "#endif",
    "    if (yyssp >= yyss + yystacksize - 1)",
    "    {",
    "        goto yyoverflow;",
    "    }",
    "    *++yyssp = yystate;",
    "    *++yyvsp = yyval;",
    "    goto yyloop;",
    "yyoverflow:",
    "    yyerror(\"yacc stack overflow\");",
    "yyabort:",
    "    return (1);",
    "yyaccept:",
    "    return (0);",
    "}",
    (char *) NULL
};

static char *perl_trailer[] =
{
    "    $p->{'yyssp'} -= $p->{'yym'};",
    "    $p->{'yystate'} = $p->{'yyss'}->[$p->{'yyssp'}];",
    "    $p->{'yyvsp'} -= $p->{'yym'};",
    "    $p->{'yym'} = $yylhs[$p->{'yyn'}];",
    "    if ($p->{'yystate'} == 0 && $p->{'yym'} == 0)",
    "    {",
    "      warn(\"yydebug: after reduction, shifting from state 0 \",",
    "            \"to state $YYFINAL\\n\") if $p->{'yydebug'};",
    "      $p->{'yystate'} = $YYFINAL;",
    "      $p->{'yyss'}->[++$p->{'yyssp'}] = $YYFINAL;",
    "      $p->{'yyvs'}->[++$p->{'yyvsp'}] = $p->{'yyval'};",
    "      if ($p->{'yychar'} < 0)",
    "      {",
    "        if ((($p->{'yychar'}, $p->{'yylval'}) = ",
    "            &{$p->{'yylex'}}($s)) < 0) { $p->{'yychar'} = 0; }",
    "        if ($p->{'yydebug'})",
    "        {",
    "          $p->{'yys'} = '';",
    "          if ($p->{'yychar'} <= $#yyname) ",
    "            { $p->{'yys'} = $yyname[$p->{'yychar'}]; }",
    "          if (!$p->{'yys'}) { $p->{'yys'} = 'illegal-symbol'; }",
    "          warn(\"yydebug: state $YYFINAL, reading \" . ",
    "               $p->{'yychar'} . \" (\" . $p->{'yys'} . \")\\n\");",
    "        }",
    "      }",
    "      return ($p->{'yyvs'}->[1]) if $p->{'yychar'} == 0;",
    "      next yyloop;",
    "    }",
    "    if (($p->{'yyn'} = $yygindex[$p->{'yym'}]) && ",
    "        ($p->{'yyn'} += $p->{'yystate'}) >= 0 && ",
    "        $p->{'yyn'} <= $#yycheck && ",
    "        $yycheck[$p->{'yyn'}] == $p->{'yystate'})",
    "    {",
    "        $p->{'yystate'} = $yytable[$p->{'yyn'}];",
    "    } else {",
    "        $p->{'yystate'} = $yydgoto[$p->{'yym'}];",
    "    }",
    "    warn(\"yydebug: after reduction, shifting from state \" . ",
    "        $p->{'yyss'}->[$p->{'yyssp'}] . \" to state \" . ",
    "        $p->{'yystate'} . \"\\n\") if $p->{'yydebug'};",
    "    $p->{'yyss'}[++$p->{'yyssp'}] = $p->{'yystate'};",
    "    $p->{'yyvs'}[++$p->{'yyvsp'}] = $p->{'yyval'};",
    "  } # yyloop",
    "} # yyparse",
    (char *) NULL
};

char **trailer[] = { c_trailer, perl_trailer };

#if __STDC__
static char *add_prefixes(char *old_str, char *new_str)
#else
static char *add_prefixes(old_str, new_str)
char *old_str;
char *new_str;
#endif
{
    register char *from = old_str;
    register char *to = new_str;
    register char *p;

    while (*from) {
	if (*from == 'Y' && *(from + 1) == 'Y') {
	    from += 2;
	    p = define_prefix;
	    while (*to++ = *p++)
		/* void */ ;
	    to--;
	}
	else if (*from == 'y' && *(from + 1) == 'y') {
	    from += 2;
	    p = symbol_prefix;
	    while (*to++ = *p++)
		/* void */ ;
	    to--;
	}
	else {
	    *to++ = *from++;
	}
    }

    *to = *from;
    
    return new_str;
}

#if __STDC__
void write_section(char **section[])
#else
void write_section(section)
char **section[];
#endif
{
    register int i;
    register FILE *fp;
    register char **sec = section[(int) language];

    if (sec != (char **) NULL)
    {
	fp = code_file;
	if (prefix_changed)
	{
	    char buf[BUFSIZ];

	    for (i = 0; sec[i]; ++i)
	    {
		++outline;
		fprintf(fp, "%s\n", add_prefixes(sec[i], buf));
	    }
	}
	else
	{
	    for (i = 0; sec[i]; ++i)
	    {
		++outline;
		fprintf(fp, "%s\n", sec[i]);
	    }
	}
    }
}
