/*==============================================================================
| pg output module for netl
|   by Graham THE Ollis <ollisg@netl.org>
|
|   Copyright (C) 2000 Graham THE Ollis <ollisg@netl.org>
|
|   This program is free software; you can redistribute it and/or modify
|   it under the terms of the GNU General Public License as published by
|   the Free Software Foundation; either version 2 of the License, or
|   (at your option) any later version.
|
|   This program is distributed in the hope that it will be useful,
|   but WITHOUT ANY WARRANTY; without even the implied warranty of
|   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|   GNU General Public License for more details.
|
|   You should have received a copy of the GNU General Public License
|   along with this program; if not, write to the Free Software
|   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
|=============================================================================*/

#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>

#include "netl/global.h"

#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"

#ifdef BOOL_THREADED
fun_prefix int action_done[PTHR_MAXTHREADS];
#include <pthread.h>
static pthread_mutex_t dbmutex;
#define lock() pthread_mutex_lock(&dbmutex)
#define unlock() pthread_mutex_lock(&dbmutex)
#else
fun_prefix int action_done;
#define lock()
#define unlock()
#endif

fun_prefix char *
	pghost = NULL,
	pgport = NULL,
	pgoptions = NULL,
	pgtty = NULL,
	dbName = NULL,
	login = NULL,
	pwd = NULL;

/*==============================================================================
| stub
|=============================================================================*/

fun_prefix void
action(u8 *dg, struct configitem *cf, size_t len, int tid)
{
	#ifdef BOOL_THREADED
		action_done[tid] = TRUE;
	#else
		action_done = TRUE;
	#endif

	lock();
	/* ## FIXME ## */
	unlock();
}

static PGconn conn;

fun_prefix void
construct(void)
{
	conn = PQSetdbLogin(pghost, pgport, pgoptions, pgtty,
				dbName, login, pwd);
	if(PQstatus(conn) == CONNECTION_BAD) {
		err("error accessing pgsql: %s", PQerrorMessage(conn));
		exit(1);
	}

	#ifdef BOOL_THREADED
		pthread_mutex_init(&dbmutex, NULL);
	#endif
}

fun_preix void
destruct(void)
{
	PQfinish(conn)
}

#if BOOL_DYNAMIC_MODULES == 0
void
out_pg_register_symbols(void)
{
	register_symbol("out/pg.so", "action_done", &action_done);
	register_symbol("out/pg.so", "action", action);
	register_symbol("out/pg.so", "construct", construct);
	register_symbol("out/pg.so", "destruct", destruct);

	register_symbol("out/pg.so", "pghost", pghost);
	register_symbol("out/pg.so", "pgport", pgport);
	register_symbol("out/pg.so", "pgoptions", pgoptions);
	register_symbol("out/pg.so", "pgtty", pgtty);
	register_symbol("out/pg.so", "dbName", dbName);
	register_symbol("out/pg.so", "login", login);
	register_symbol("out/pg.so", "pwd", pwd);
}
#endif


