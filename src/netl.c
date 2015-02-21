/*==============================================================================
| netl
|   optimized (and debugged) by Graham THE Ollis <ollisg@netl.org>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@netl.org>
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

#include "netl/version.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#ifndef NO_NETDB_H
#include <netdb.h>
#endif
#include <time.h>
#ifdef BOOL_THREADED
#include <pthread.h>
#endif

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"

#include "netl/netl.h"
#include "netl/sighandle.h"
#include "netl/io.h"
#include "netl/options.h"
#include "netl/filter.h"
#include "netl/action.h"
#include "netl/config.h"
#include "netl/resolve.h"
#include "netl/grab.h"
#include "netl/check.h"
#include "netl/compiler.h"

/*==============================================================================
| GLOBALS
| + grab is a pointer to the function which actually collects the packets as
|   they pass by.
|=============================================================================*/

/* grab globals */
void *netl_guts_grab_module = NULL;
static unsigned char * (*grab)(int *);
static int *offset;

/*==============================================================================
| prepare dl wrapper
| + calls the dynamic device preperation routine in the input or grab module.
|=============================================================================*/

static char *
prepare(char *dev)
{
	char str_buffer[1024];
	char *(*prepare_function)(char *);
	extern char *netl_config_nm_input_name;

	if(netl_guts_grab_module != NULL) {
		nmclose(netl_guts_grab_module);
	}
/* !! FIXME !! need a general fix for this, for platforms too stupid to have
 |		a snprintf
 */
#ifdef NO_SNPRINTF
	sprintf(str_buffer, "%s/in/%s.so", netl_config_so_path, netl_config_nm_input_name);
#else
	snprintf(str_buffer, 1024, "%s/in/%s.so", netl_config_so_path, netl_config_nm_input_name);
#endif
	netl_guts_grab_module = nmopen(str_buffer);

	prepare_function = nmsym(netl_guts_grab_module, "prepare");
	offset = nmsym_nofail(netl_guts_grab_module, "offset");
	if(offset != NULL && *offset != 14)	/* FIXME */
		err("warning: offset returned from input module isn't 14!");

	dev = prepare_function(dev);

	grab = nmsym(netl_guts_grab_module, "grab");

	return dev;
}

/*==============================================================================
|	filter threads...
|=============================================================================*/

#ifdef BOOL_THREADED

#define BUFFER_SIZE 100

typedef void *(blarph)(void *);

typedef struct {
	char *data;
	size_t size;
} buffer_item;

static buffer_item buffer[100];
static int xbuffer_write=0, xbuffer_read=0;
static pthread_mutex_t buffer_mutex, semaphore_mutex, semaphore_mutex2;
static int semaphore_value=0;

static void
P()
{
	pthread_mutex_lock(&semaphore_mutex);

	if(--semaphore_value < 0) {
		pthread_mutex_unlock(&semaphore_mutex);
		pthread_mutex_lock(&semaphore_mutex2);
	} else {
		pthread_mutex_unlock(&semaphore_mutex);
	}

}

static void
V()
{
	pthread_mutex_lock(&semaphore_mutex);

	if(++semaphore_value <= 0) {
		pthread_mutex_unlock(&semaphore_mutex2);
	}

	pthread_mutex_unlock(&semaphore_mutex);
}

static void
buffer_write(char *data, size_t size)
{
	if((xbuffer_write + 1 % BUFFER_SIZE) == xbuffer_read) {
		/* FIXME */
		err("warning: dropping packets due to pthreads\n");
		return;
	}
	pthread_mutex_lock(&buffer_mutex);
	buffer[xbuffer_write].data = data;
	buffer[xbuffer_write].size = size;
	xbuffer_write = (xbuffer_write + 1) % BUFFER_SIZE;
	pthread_mutex_unlock(&buffer_mutex);
	V();
}

static char *
buffer_read(size_t *size)
{
	char *ret;
	P();
	pthread_mutex_lock(&buffer_mutex);
	ret = buffer[xbuffer_read].data;
	*size = buffer[xbuffer_read].size;
	xbuffer_read = (xbuffer_read + 1) % BUFFER_SIZE;
	pthread_mutex_unlock(&buffer_mutex);
	return ret;
}

static void *
th_filter(int tid)
{
	char *data;
	size_t size;
	int i;
	while(47) {
		data = buffer_read(&size);

		for(i=0; i<num_acts; i++) {
			(acts[i]).action_done[tid] = FALSE;
		}
		for(i=0; i<num_filters; i++) {
			(*filters[i].check)(data, size, tid);
		}

		free(data);
	}
}

#endif

/*==============================================================================
| void netl(char *)
| + this is where the main loop lives.
| + we call grab(), which is dynamic from the LIB/in directory.
| + check() is a dynamic routine from LIB/filt and will be a filter.
|   if a check() routine wants to force netl to re-read the config file, then
|   it sets reload_config_file before returning.
|=============================================================================*/

int reload_config_file = 0;

/* 26 may 2000
 | !! FIXME !! the days where this function is named what it is named are
 | numbered.  it's confusing, because it would show up in the man pages as
 | netl(3), which you would see before seeing netl(8) [ which is a much more
 | important man page ].  i am considering calling this function netl_netl(3)
 | and then adding a macro in the header files somewhere
 | #define netl netl_netl
 | so if you don't like that, come up with a better name, and let me know.
 */

int
netl(char *dev)
{
	int l;
	unsigned char *buf;
	#ifdef BOOL_THREADED
		int i;
		extern int netl_num_threads;

	#endif

	ope("netl");
	log("starting netl, logging %s", dev);

	prepare(dev);

	#ifdef BOOL_THREADED
		pthread_mutex_init(&buffer_mutex, NULL);
		pthread_mutex_init(&semaphore_mutex, NULL);
		pthread_mutex_init(&semaphore_mutex2, NULL);
		pthread_mutex_lock(&semaphore_mutex2);
		for(i=0; i<netl_num_threads; i++) {
			pthread_t thread;
			if(pthread_create(	&thread, NULL, 
						th_filter, 
						(void *)(long)i) != 0 ||
			   pthread_detach(thread) != 0) {
				err("Error creating thread");
				exit(1);
			}
		}
	#endif

	/*============================================================================
	| Entering the data collection loop
	|===========================================================================*/

	while(47) {			/* valnumdez's NoOp */
		if((buf = grab(&l)) == NULL) {
			log(strerror(errno));
			err("Error receiving RAW packet");
		} else {
			#if BOOL_THREADED
				{
					char *tmp = malloc(l);
					memcpy(tmp, buf, l);
					buffer_write(tmp, l);
				}
			#else
				netl_packet_check(buf, l);
			#endif
		}

		if(reload_config_file) {
			reload_config_file = 0;

			clearipcache();
			log("old ip cache cleared");

			netl_config_clear();

			netl_config_pre();
			#ifdef NO_SYSLOGD
				netl_config_readfile(configfile);
			#else
				netl_config_readfile(configfile, noBackground);
			#endif
			netl_config_post();
			log("re-read configfile %s", configfile);
			#ifdef BOOL_THREADEDED
				err("warning: config reloading is not thread safe!");
			#endif
		}
	}

	return 0;
}
