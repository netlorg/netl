#===============================================================================
# here is the stuff you may be interested in changing.
#===============================================================================

CC=gcc
CFLAGS=-O3 -Wall
#CFLAGS=-g3 -Wall #-DYY_NO_UNPUT
LDFLAGS=-L. -rdynamic

LEX=flex
LEXFLAGS=-F
LEX_LIBS=-lfl

YACC=bison
YACCFLAGS=-v -d
YACC_LIBS=

AR=ar
RANLIB=ranlib
LN=ln
RM=rm -f
CP=cp
PGP=pgp262
M4=m4
M4FLAGS=

VER=1.02

PREFIX=/usr/local
SUBINPATH=$(PREFIX)/sbin
BINPATH=$(PREFIX)/bin
MANPATH=$(PREFIX)/man
LIBPATH=$(PREFIX)/lib/netl-$(VER)
INCLUDEPATH=$(LIBPATH)/include

NET_LIBS=
MISC_LIBS=-ldl

