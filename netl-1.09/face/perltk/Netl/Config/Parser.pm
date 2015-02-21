#line 3 ""







BEGIN { $warning_save = $^W; $^W = 0 }
package Netl::Config::Parser;

#===============================================================================
# do not attempt to modify Parser.pm by had, it is generated from config.y
# in the netl base distribution.
# there are a few globals which are set after the parser completes.
#
#	@rules		. list of rules [ [action ...], protocol, fields ... ]
#	$libdir		. final library directory specified (iff specified)
#	$dumpdir	. final dump directory specified (iff specified)
#	$listenport	. argument of listen directive
#	$detect		. true iff detect directive appears
#	%alias		. IP aliases
#===============================================================================




#line 33 ""
#typedef union {
#	union_thingie x;
#	char *s;
#	int i;
#	u8 hw[6];
#	union ip6addr ip6a;
#} YYSTYPE;
#line 40 "y.tab.pl"
$CON_STR=257;
$CON_INT=258;
$RULE_DEVICE=259;
$RULE_DETECT=260;
$RULE_ALIAS=261;
$RULE_LISTEN=262;
$RULE_T=263;
$RULE_DIR_LIB=264;
$RULE_DIR_DUMP=265;
$FLD_NAME=266;
$FLD_FLAG=267;
$FLD_DSTPORT=268;
$FLD_SRCPORT=269;
$FLD_DSTIP=270;
$FLD_SRCIP=271;
$FLD_DSTHW=272;
$FLD_SRCHW=273;
$FLD_TYPE=274;
$FLD_TYPE6=275;
$FLD_CODE=276;
$FLG=277;
$PROT=278;
$NL=279;
$KEY_IF=280;
$KEY_AND=281;
$KEY_OR=282;
$YYERRCODE=256;
@yylhs = (                                               -1,
    0,    0,    1,    1,    3,    3,    4,    4,    2,    2,
    2,    2,    2,    2,    2,    2,    2,    2,    2,    5,
    5,    5,    5,    5,    5,    5,    5,    5,    6,    6,
    6,    7,    7,    7,    7,    8,    8,    8,    8,    8,
    8,    8,    8,    8,    8,    8,    8,    8,    8,   12,
   12,   12,    9,    9,   10,   10,   14,   13,   11,   15,
   15,
);
@yylen = (                                                2,
    1,    0,    2,    1,    1,    0,    3,    1,    4,    2,
    4,    3,    3,    3,    2,    7,    5,    1,    2,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    3,
    0,    2,    3,    3,    1,    3,    3,    3,    5,    3,
    5,    3,    4,    4,    3,    3,    3,    3,    3,    2,
   10,    0,    1,    0,    3,    1,    1,   11,   17,    1,
    0,
);
@yydefred = (                                             0,
    0,    0,    0,    0,    0,    0,    0,    0,   18,    0,
    0,    0,    4,   19,   20,   21,   22,   23,   24,   25,
   26,   28,   27,    0,   10,    0,    0,   15,    0,    0,
    0,    0,    0,    3,    0,    0,   12,    5,    0,   13,
   14,    0,    0,    9,   11,    0,   53,    0,    0,   35,
    0,    7,    0,    0,   17,    0,    0,   32,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   30,   33,   34,   36,   57,    0,   56,    0,    0,    0,
    0,   42,    0,    0,   45,   46,   47,   48,   49,    0,
    0,    0,    0,   60,    0,    0,   43,   44,    0,   16,
   55,   39,   41,    0,   50,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   51,
   58,    0,    0,    0,    0,    0,   59,
);
@yydgoto = (                                             11,
   12,   13,   39,   33,   24,   48,   49,   50,   51,   76,
   82,   97,   85,   77,   95,
);
@yysindex = (                                           -59,
 -274, -205, -264, -205, -248, -260, -238, -237,    0, -241,
    0,  -59,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -205,    0, -205, -255,    0, -253, -247,
 -246,   -8,  -25,    0, -240, -239,    0,    0,  -26,    0,
    0, -241, -235,    0,    0,    5,    0, -233,   -3,    0,
 -162,    0, -253,  -20,    0,    5,    5,    0, -205, -229,
 -214, -209,  -89, -205, -208, -208, -205, -205, -205,  -26,
    0,    0,    0,    0,    0,   16,    0,   17,   19, -195,
   20,    0,   20,   29,    0,    0,    0,    0,    0, -191,
 -229, -184, -157,    0,   44,  -37,    0,    0, -132,    0,
    0,    0,    0, -195,    0, -131,   70,   71,   84, -127,
 -195, -126,   75,   76,   89, -122, -195, -121,   80,   81,
   94, -117, -195, -116,   85,   86,  104, -112, -195,    0,
    0,   90, -195,   91, -195,   54,    0,
);
@yyrindex = (                                           150,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  151,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   35,    0,
    0,   92,    0,    0,    0,    0,    0,    0, -190,    0,
    0,    0,    0,    0,    0, -151,    0,    0, -176,    0,
    0,    0,   35, -151,    0, -151, -151,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -190,
    0,    0,    0,    0,    0,  -33,    0,  -16,    1,   95,
   18,    0,   18,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   95,    0,    0,    0,    0,    0,    0,
   95,    0,    0,    0,    0,    0,   95,    0,    0,    0,
    0,    0,   95,    0,    0,    0,    0,    0,   95,    0,
    0,    0,   95,    0,   59,    0,    0,
);
@yygindex = (                                             0,
    0,  143,  103,  115,    2,   88,  113,  -45,    0,    0,
    0,   77,   96,   72,  -88,
);
$YYTABLESIZE=314;
@yytable = (                                             37,
   10,   80,  106,   58,   14,   26,   47,   37,   58,   27,
   72,   73,   47,   46,   25,  108,   38,   29,   30,   31,
   71,   32,  114,   37,   38,   35,   38,   36,  120,   47,
   28,   40,   41,   40,  126,   42,   43,   47,   44,   45,
  132,   40,   53,   78,  134,   55,  136,   75,   79,   84,
   52,   15,   16,   17,   18,   19,   20,   21,   52,   91,
   74,   92,   94,   93,   81,   83,   96,    6,   87,   88,
   89,   22,   23,  102,    6,   54,   54,   54,   54,   54,
   54,   54,   54,   54,   54,   54,   99,  100,   31,   54,
   54,   54,   54,   54,   54,   54,   54,   54,   54,   54,
  103,  104,   29,   59,   60,   61,   62,   63,   64,   65,
   66,   67,   68,   69,   54,   54,   54,   54,   54,   54,
   54,   54,   54,   54,   54,  107,  109,  110,  111,  112,
  113,  115,  116,  117,  118,  119,  121,  122,  123,  124,
  125,  127,  128,  129,  130,  131,  137,  133,  135,    2,
    1,   61,   61,    8,   34,   70,   52,   90,   54,   98,
    0,   86,  101,    0,    0,    0,    0,   15,   16,   17,
   18,   19,   20,   21,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   22,   23,    0,
    0,    0,    0,    0,    0,    0,    1,    0,    0,    2,
    3,    4,    5,    6,    7,    8,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    9,
  105,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   37,   37,   37,   37,   37,   37,   37,   37,
   37,   37,   37,    0,    0,   37,    0,   37,   37,   38,
   38,   38,   38,   38,   38,   38,   38,   38,   38,   38,
   56,   57,   38,    0,   38,   38,   40,   40,   40,   40,
   40,   40,   40,   40,   40,   40,   40,   56,   57,   40,
    0,   40,   40,   52,   52,   52,   52,   52,   52,   52,
   52,   52,   52,   52,    0,    0,   52,    0,   52,   52,
    6,    6,    6,    6,    6,    6,    6,    6,    6,    6,
    6,    0,    0,    6,
);
@yycheck = (                                             33,
   60,   91,   40,   49,  279,    4,   33,   41,   54,  258,
   56,   57,   33,   40,  279,  104,   33,  278,  257,  257,
   41,  263,  111,  279,   41,   24,  280,   26,  117,   33,
  279,  279,  279,   33,  123,   44,   62,   33,  279,  279,
  129,   41,  278,  258,  133,  279,  135,  277,  258,  258,
   33,  257,  258,  259,  260,  261,  262,  263,   41,   44,
   59,   45,  258,   45,   63,   64,   47,   33,   67,   68,
   69,  277,  278,  258,   40,  266,  267,  268,  269,  270,
  271,  272,  273,  274,  275,  276,   58,  279,  279,  266,
  267,  268,  269,  270,  271,  272,  273,  274,  275,  276,
  258,   58,  279,  266,  267,  268,  269,  270,  271,  272,
  273,  274,  275,  276,  266,  267,  268,  269,  270,  271,
  272,  273,  274,  275,  276,  258,  258,   58,   58,   46,
  258,  258,   58,   58,   46,  258,  258,   58,   58,   46,
  258,  258,   58,   58,   41,  258,   93,   58,   58,    0,
    0,   93,   58,   62,   12,   53,   42,   70,   46,   83,
   -1,   66,   91,   -1,   -1,   -1,   -1,  257,  258,  259,
  260,  261,  262,  263,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  277,  278,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  256,   -1,   -1,  259,
  260,  261,  262,  263,  264,  265,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  279,
  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  266,  267,  268,  269,  270,  271,  272,  273,
  274,  275,  276,   -1,   -1,  279,   -1,  281,  282,  266,
  267,  268,  269,  270,  271,  272,  273,  274,  275,  276,
  281,  282,  279,   -1,  281,  282,  266,  267,  268,  269,
  270,  271,  272,  273,  274,  275,  276,  281,  282,  279,
   -1,  281,  282,  266,  267,  268,  269,  270,  271,  272,
  273,  274,  275,  276,   -1,   -1,  279,   -1,  281,  282,
  266,  267,  268,  269,  270,  271,  272,  273,  274,  275,
  276,   -1,   -1,  279,
);
$YYFINAL=11;
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
$YYMAXTOKEN=282;
#if YYDEBUG
@yyname = (
"end-of-file",'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
"'!'",'','','','','','',"'('","')'",'','',"','","'-'","'.'","'/'",'','','','','','','','','','',
"':'",'',"'<'",'',"'>'",'','','','','','','','','','','','','','','','','','','','','','','','','','','','',
"'['",'',"']'",'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',
'','','','','','','','','','',"CON_STR","CON_INT","RULE_DEVICE","RULE_DETECT",
"RULE_ALIAS","RULE_LISTEN","RULE_T","RULE_DIR_LIB","RULE_DIR_DUMP","FLD_NAME",
"FLD_FLAG","FLD_DSTPORT","FLD_SRCPORT","FLD_DSTIP","FLD_SRCIP","FLD_DSTHW",
"FLD_SRCHW","FLD_TYPE","FLD_TYPE6","FLD_CODE","FLG","PROT","NL","KEY_IF",
"KEY_AND","KEY_OR",
);
@yyrule = (
"\$accept : start",
"start : lines",
"start :",
"lines : lines line",
"lines : line",
"op_if : KEY_IF",
"op_if :",
"rule_t_list : RULE_T ',' rule_t_list",
"rule_t_list : RULE_T",
"line : RULE_DEVICE str str NL",
"line : RULE_DETECT NL",
"line : RULE_ALIAS str str NL",
"line : RULE_LISTEN CON_INT NL",
"line : RULE_DIR_LIB CON_STR NL",
"line : RULE_DIR_DUMP CON_STR NL",
"line : RULE_LISTEN NL",
"line : '<' rule_t_list '>' PROT op_if op_flds NL",
"line : RULE_T PROT op_if op_flds NL",
"line : NL",
"line : error NL",
"str : CON_STR",
"str : CON_INT",
"str : RULE_DEVICE",
"str : RULE_DETECT",
"str : RULE_ALIAS",
"str : RULE_LISTEN",
"str : RULE_T",
"str : PROT",
"str : FLG",
"op_flds : flds",
"op_flds : '(' flds ')'",
"op_flds :",
"flds : flds fld",
"flds : flds KEY_AND fld",
"flds : flds KEY_OR fld",
"flds : fld",
"fld : op_not FLD_NAME str",
"fld : op_not FLD_FLAG flgs",
"fld : op_not FLD_DSTPORT CON_INT",
"fld : op_not FLD_DSTPORT CON_INT '-' CON_INT",
"fld : op_not FLD_SRCPORT CON_INT",
"fld : op_not FLD_SRCPORT CON_INT '-' CON_INT",
"fld : op_not FLD_DSTIP ip6addr",
"fld : op_not FLD_DSTIP str op_bitmask",
"fld : op_not FLD_SRCIP str op_bitmask",
"fld : op_not FLD_DSTHW hw",
"fld : op_not FLD_SRCHW hw",
"fld : op_not FLD_TYPE str",
"fld : op_not FLD_TYPE6 str",
"fld : op_not FLD_CODE str",
"op_bitmask : '/' CON_INT",
"op_bitmask : '/' '(' CON_INT '.' CON_INT '.' CON_INT '.' CON_INT ')'",
"op_bitmask :",
"op_not : '!'",
"op_not :",
"flgs : flgs ',' flg",
"flgs : flg",
"flg : FLG",
"hw : CON_INT ':' CON_INT ':' CON_INT ':' CON_INT ':' CON_INT ':' CON_INT",
"ip6addr : '[' op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ']'",
"op_con_int : CON_INT",
"op_con_int :",
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
if ($p->{'yyn'} == 7) {
#line 63 ""
{
# 171 ""



 						my $fred = $3;
 						$$ = [ $1, @{$fred} ];
 


					}
}
if ($p->{'yyn'} == 8) {
#line 73 ""
{
# 188 ""



 						$$ = [ $1 ];
 


					}
}
if ($p->{'yyn'} == 9) {
#line 84 ""
{ 



					}
}
if ($p->{'yyn'} == 10) {
#line 89 ""
{





 						$detect = 1;
 


					}
}
if ($p->{'yyn'} == 11) {
#line 99 ""
{








 						$alias{ $2 } = $3;
 


					}
}
if ($p->{'yyn'} == 12) {
#line 112 ""
{







 						$listenport = $2;
 


					}
}
if ($p->{'yyn'} == 13) {
#line 125 ""
{






 						$libdir = $2;
 


					}
}
if ($p->{'yyn'} == 14) {
#line 137 ""
{






 						$dumpdir = $2;
 


					}
}
if ($p->{'yyn'} == 15) {
#line 148 ""
{







 						$listenport = 47;
 


					}
}
if ($p->{'yyn'} == 16) {
#line 161 ""
{
# 293 ""



 						my $flds = $6;
 				push @rules, 
 					[ $line_number, $2, $4, 
 						flds2hash(@{ $flds }) ];
 


					}
}
if ($p->{'yyn'} == 17) {
#line 174 ""
{
# 326 ""



 						my $flds = $4;
 				push @rules, 
 					[ $line_number, [ $1 ], $2, 
 						flds2hash(@{ $flds }) ];
 


					}
}
if ($p->{'yyn'} == 19) {
#line 187 ""
{ yyerrok; }
}
if ($p->{'yyn'} == 20) {
#line 190 ""
{ 





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 21) {
#line 200 ""
{





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 22) {
#line 210 ""
{





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 23) {
#line 220 ""
{





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 24) {
#line 230 ""
{





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 25) {
#line 240 ""
{





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 26) {
#line 250 ""
{





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 27) {
#line 260 ""
{





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 28) {
#line 270 ""
{





 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 29) {
#line 282 ""
{


 						$$ = $1;
 


					}
}
if ($p->{'yyn'} == 30) {
#line 290 ""
{


 						$$ = $2;
 


					}
}
if ($p->{'yyn'} == 31) {
#line 298 ""
{


 						$$ = [ ];
 


					}
}
if ($p->{'yyn'} == 32) {
#line 307 ""
{


 						my $fred = $1;
 						$$ = [ @{$fred}, $2 ];
 


					}
}
if ($p->{'yyn'} == 33) {
#line 315 ""
{


 						my $fred = $1;
 						$$ = [ @{$fred}, $3 ];
 


					}
}
if ($p->{'yyn'} == 34) {
#line 323 ""
{


 						die "or is unimplemented.";
 


					}
}
if ($p->{'yyn'} == 35) {
#line 330 ""
{


 						$$ = [ $1 ];
 


					}
}
if ($p->{'yyn'} == 36) {
#line 340 ""
{









 				$$ = [ 'name', $3 ];
 


			}
}
if ($p->{'yyn'} == 37) {
#line 355 ""
{
# 520 ""



 				if($1) {
 					$$ = [ '!flag', $3 ];
 				} else {
 					$$ = [ 'flag', $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 38) {
#line 369 ""
{
# 542 ""



 				if($1) {
 					$$ = [ '!dstport', $3, $3 ];
 				} else {
 					$$ = [ 'dstport', $3, $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 39) {
#line 383 ""
{
# 568 ""



 				if($1) {
 					$$ = [ '!dstport', $3, $5 ];
 				} else {
 					$$ = [ 'dstport', $3, $5 ];
 				}
 


			}
}
if ($p->{'yyn'} == 40) {
#line 397 ""
{
# 590 ""



 				if($1) {
 					$$ = [ '!srcport', $3, $3 ];
 				} else {
 					$$ = [ 'srcport', $3, $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 41) {
#line 411 ""
{
# 616 ""



 				if($1) {
 					$$ = [ '!srcport', $3, $5 ];
 				} else {
 					$$ = [ 'srcport', $3, $5 ];
 				}
 


			}
}
if ($p->{'yyn'} == 42) {
#line 425 ""
{
# 638 ""



 				if($1) {
 					$$ = [ '!ip6addr', $3 ];
 				} else {
 					$$ = [ 'ip6addr', $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 43) {
#line 439 ""
{
# 667 ""



 				if($1) {
 					$$ = [ '!dstip', $3, $4 ];
 				} else {
 					$$ = [ 'dstip', $3, $4 ];
 				}
 


			}
}
if ($p->{'yyn'} == 44) {
#line 453 ""
{
# 696 ""



 				if($1) {
 					$$ = [ '!srcip', $3, $4 ];
 				} else {
 					$$ = [ 'srcip', $3, $4 ];
 				}
 


			}
}
if ($p->{'yyn'} == 45) {
#line 467 ""
{
# 717 ""



 				if($1) {
 					$$ = [ '!dsthw', $3 ];
 				} else {
 					$$ = [ 'dsthw', $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 46) {
#line 481 ""
{
# 738 ""



 				if($1) {
 					$$ = [ '!srchw', $3 ];
 				} else {
 					$$ = [ 'srchw', $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 47) {
#line 495 ""
{
# 765 ""



 				if($1) {
 					$$ = [ '!type', $3 ];
 				} else {
 					$$ = [ 'type', $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 48) {
#line 509 ""
{
# 795 ""




 				if($1) {
 					$$ = [ '!type6', $3 ];
 				} else {
 					$$ = [ 'type6', $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 49) {
#line 524 ""
{
# 826 ""




 				if($1) {
 					$$ = [ '!code', $3 ];
 				} else {
 					$$ = [ 'code', $3 ];
 				}
 


			}
}
if ($p->{'yyn'} == 50) {
#line 541 ""
{










 				$$ = (0xffffffff) << (32 - $2);
 


			}
}
if ($p->{'yyn'} == 51) {
#line 557 ""
{
# 866 ""




 				$$ = $3 * 0x1000000 +
 				     $5 *   0x10000 +
 				     $7 *     0x100 +
 				     $9;
 


			}
}
if ($p->{'yyn'} == 52) {
#line 570 ""
{





 				$$ = 0xffffffff;
 


			}
}
if ($p->{'yyn'} == 53) {
#line 582 ""
{





 				$$ = 1;
 


			}
}
if ($p->{'yyn'} == 54) {
#line 592 ""
{





 				$$ = 0;
 


			}
}
if ($p->{'yyn'} == 55) {
#line 605 ""
{





 				my $fred = $1;
 				$$ = [ @{$fred}, $3 ];
 


			}
}
if ($p->{'yyn'} == 56) {
#line 616 ""
{





 				$$ = [ $1 ];
 


			}
}
if ($p->{'yyn'} == 57) {
#line 628 ""
{
# 957 ""




 				$$ = $1;
 


			}
}
if ($p->{'yyn'} == 58) {
#line 642 ""
{










 				$$ = [ $1, $3, $5, $7, $9, $11 ];
 


			}
}
if ($p->{'yyn'} == 59) {
#line 661 ""
{
# 998 ""



 				$$ = [ $2,  $4,  $6,  $8, $10, $12, $14, $16 ];
 


			}
}
if ($p->{'yyn'} == 60) {
#line 673 ""
{






 				$$ = $1;
 


			}
}
if ($p->{'yyn'} == 61) {
#line 684 ""
{





 				$$ = 0;
 


			}
}
#line 1214 "y.tab.pl"
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
#line 696 ""

# 1408 ""




BEGIN {
	$regex = qr{^
			(\n)|				# 1 new line
			([ \t]+)|			# 2 white space
			(\#.*?\n)|			# 3 comment
			(".*?")|			# 4 string
			(\(|\{|\)|\})|			# 5 brace
			(\;)|				# 6 thingie
			(if|and|\&\&|or|\|\||
			 device|detect|alias|listen|
			 dir[ ]lib|dir[ ]dump|
			 ignore|log|dump|dl|null|
			 pipe)|				# 7 other thingies
			(\@[a-zA-Z0-9\._]+)|		# 8 $ACTION_USER 
			(raw|tcp|icmp|ignp|udp|ip|
			 tcp4|icmp4|ignp4|udp4|ip4|
			 tcp6|icmp6|ignp6|udp6|ip6)|	# 9 protocols
			(\&[a-zA-Z0-9\._]+)|		# 10 $PROT_USER
			(
			 (?:
				name|flag|
				(?:dst|src)(?:port|ip|hw)|
				type|type6|code|
			 )=)|				# 11 $FLD_*
			(urg|ack|psh|rsh|syn|fin|all)|	# 12 FLG
			([a-zA-Z0-9\._]+)|		# 13 CON_STR
			([0-9A-Fa-f]+)|			# 14 number
			(.)				# 15 unhandled character
			}imx;
}

%yylex = (
	'if'		=>	$KEY_IF,
	'and'		=>	$KEY_AND,
	'&&'		=>	$KEY_AND,
	'or'		=>	$KEY_OR,
	'||'		=>	$KEY_OR,
	'device'	=>	$RULE_DEVICE,
	'detect'	=>	$RULE_DETECT,
	'alias'		=>	$RULE_ALIAS,
	'listen'	=>	$RULE_LISTEN,
	'dir lib'	=>	$RULE_DIR_LIB,
	'dir dump'	=>	$RULE_DIR_DUMP,
	'ignore'	=>	$RULE_T,
	'log'		=>	$RULE_T,
	'dump'		=>	$RULE_T,
	'dl'		=> 	$RULE_T,
	'null'		=>	$RULE_T,
	'pipe'		=>	$RULE_T,
	'name='		=>	$FLD_NAME,
	'flag='		=>	$FLD_FLAG,
	'dstport='	=>	$FLD_DSTPORT,
	'srcport='	=>	$FLD_SRCPORT,
	'dstip='	=>	$FLD_DSTIP,
	'srcip='	=>	$FLD_SRCIP,
	'dsthw='	=>	$FLD_DSTHW,
	'srchw='	=>	$FLD_SRCHW,
	'type='		=>	$FLD_TYPE,
	'type6='	=>	$FLD_TYPE6,
	'code='		=>	$FLD_CODE,
	'urg'		=>	$FLG,
	'ack'		=>	$FLG,
	'psh'		=>	$FLG,
	'rst'		=>	$FLG,
	'syn'		=>	$FLG,
	'fin'		=>	$FLG,
	'all'		=>	$FLG,
);

sub yylex {
	($id, $val) = _yylex(@_);
	#print STDERR "id:$id, val:$val\n";
	return ($id, $val);
}

sub _yylex {
	if(defined @yylex_next) {
		my @save = @yylex_next;
		undef @yylex_next;
		return @save;
	}

	return 0 if $done;

	unless(defined $input) {
		$save = $/;
		$input = <STDIN>;
		$/ = $save;
		$line_number = 1;
		# @source = split /\n/m, $input;
	}

fred:	while($input ne '') {
		if($input =~ s/$regex//) {
			#=======================================================
			# $1 new line and $3 comment (both mean a \n)
			#=======================================================

			if(($1 ne '') or ($3 ne '') or ($6 ne '')) {
				$line_number++;
				return ($NL, '');
			}

			#=======================================================
			# $2 white space (ignore)
			#=======================================================

			next fred if $2 ne '';

			#=======================================================
			# $4 quotation
			#=======================================================

			if($4 ne '') {
				my $val = $4;
				$val =~ s/^"//;		# "
				$val =~ s/"$//;	# "
				return ($CON_STR, $val);
			}

			#=======================================================
			# $5 brace
			#=======================================================

			if($5 ne '') {
				return (ord($5), $5);
			}

			#=======================================================
			# $7 value-less returns
			#=======================================================

			if($7 ne '') {
				return ($yylex{$7}, $7);
			}

			#=======================================================
			# $8 user action
			#=======================================================

			if($8 ne '') {
				my $val = $8;
				$val =~ s/^\@//;
				return ($RULE_T, $val);
			}

			#=======================================================
			# $9 protocol
			#=======================================================

			if($9 ne '') {
				return ($PROT, $9);
			}

			#=======================================================
			# $10 user protocol
			#=======================================================

			if($10 ne '') {
				my $val = $10;
				$val =~ s/^\&//;
				return ($PROT, $val);
			}

			#=======================================================
			# $11 FIELD_*
			#=======================================================

			if($11 ne '') {
				return ($yylex{$11}, $11);
			}

			#=======================================================
			# $12 FLG_*
			#=======================================================

			if($12 ne '') {
				return ($yylex{$12}, $12);
			}

			#=======================================================
			# $14 number
			#=======================================================

			if($14 ne '') {
				return ($CON_INT, $14);
			}


			#=======================================================
			# $13 CON_STR
			#=======================================================

			if($13 ne '') {
				#printf "(\$CON_STR, \$13) = ($CON_STR, $13)\n";
				return ($CON_STR, $13);
			}

			#=======================================================
			# $15 all other non-matching characters
			#=======================================================

			return (ord($15), $15) if $15 ne '';

			die "lex pattern grabbed nothing!\n";
		} else {
			die "serious error, compilex regex replace failed!";
		}
	}
	$done = 1;
	return 0;
}

sub yyerror {
	printf(STDERR "$_[0] on line $line_number\n");
}

sub gparse {
	$input = shift;
	my $yyerror = $_[0] || \&yyerror;
	my $parser = Netl::Config::Parser->new(\&yylex, $yyerror, 0);
	$line_number = 1;
	my $save = $^W;
	$^W = 0;
	$parser->yyparse;
	$^W = $save;
}

sub flds2hash {
	my @list = @_;
	my %hash = ();

	for(@list) {
		my($name, @val) = @{ $_ };
		$hash{$name} = [ @val ];
	}
	return %hash;
}

BEGIN { $^W = $warning_save }



#line 1511 "y.tab.pl"
