/*==============================================================================
| catch
|   Copyright (C) 1997 Graham THE Ollis <ollisg@wwa.com>
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
|
|  Date       Name	Revision
|  ---------  --------  --------
|  04 Jul 99  G. Ollis	created module
|=============================================================================*/

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "netl/global.h"

#include "netl/catch.h"
#include "netl/io.h"

/*==============================================================================
| these routines are intended to be library routines in libnetl.a or libnetl.so.
| they allow a program to fork a netl process and have the output piped back
| to the calling program, or for netl to fork a program (typically called 
| "pipeprog") and have the output piped back through a pipe.  this is useful
| for writing GUI interfaces to netl.  i am working on one in Perl/Tk and one
| in GTK++ for GNOME.  we shall see.
|
| + header is the structure which gets sent before the actual packet accross
|   the pipe.  id will always be "NETL", just so that if there is a transmission
|   error the other side will be able to tell.  str_len and packet_len indicate
|   the length of the name="" string as specified from the config file and
|   the size of the packet.  the stringn and the packet follow immediately after
|   the header.
|=============================================================================*/

typedef struct {
	char id[4];
	size_t str_len;
	size_t packet_len;
} header;

static header h;
static int fd;
static FILE *fp;

/*==============================================================================
| make the given pipe non blocking.
|=============================================================================*/

void netl_catch_prepare(int fd_val)
{
	int flags;

	fd = fd_val;

	if((flags = fcntl(fd, F_GETFL, 0)) == -1) {
		err("unable to fcntl(fd, F_GETFL, 0)\n");
		exit(1);
	}

	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		err("unable to fcntl(fd, F_SETFL, flags | O_NONBLOCK)\n");
		exit(1);
	}

	fp = fdopen(fd, "r");
	if(fp == NULL) {
		err("could not fdopen %d\n", fd);
		exit(1);
	}
}

/*==============================================================================
| fork a new netl.
| + *p is the prog name "netl" should work, if netl is in your path.
| + *a[] is the argument list.
| + netl_fork_a_netl() uses the environment var NETL_PIPE_FD to tell the forked
|   netl where the data will come from.
|=============================================================================*/

static pid_t forked_netl_pid = -1;

int
netl_fork_a_netl(char *p, char *a[])
{
	static int fd[2];
	int readfd, writefd;
	pid_t pid;
	char buff[20];  int i;

	if(forked_netl_pid != -1) {
		close(fd[0]);
		close(fd[1]);
	}

	if(pipe(fd) == -1)
		return -1;

	readfd = fd[0];
	writefd = fd[1];

	sprintf(buff, "%d", writefd);
	setenv("NETL_PIPE_FD", buff, 1);

	if(p == NULL)
		p = "netl";

	if((forked_netl_pid = pid = fork()) == 0) {
		execvp(p, a);
		fprintf(stderr, "%s: error execvp() %s", prog, strerror(errno));
		exit(1);
	}

	if(pid == -1) {
		close(readfd); close(writefd);
		return -1;
	}
	netl_catch_prepare(readfd);
	return pid;
}

/*==============================================================================
| given that you have forked a netl, grab any data from it, and check to
| see if it is still running.
| + returns a pointer to the packet, starting from the header.
| + returns ->.packet_len = -1 when netl has died for some reason.
| + returns NULL if there was nothing caught.
|=============================================================================*/

ret_entry *
netl_catch_catch(void)
{
	static ret_entry re = { NULL, NULL, 0 };
	int i;

	if(forked_netl_pid != -1) {
		if(waitpid(forked_netl_pid, NULL, WNOHANG)
				== forked_netl_pid) {
			re.packet_len = -1;
			return &re;
		}
	}

	for(i=0; i<10; i++) {
		if(fread(&h, sizeof(header), 1, fp) != 0) {
			if(memcmp(h.id, "NETL", 4)) {
				err("sig doesn't match \"%4s\" should be NETL\n", h.id);
				exit(1);
			}
			re.name = allocate(h.str_len);
			re.packet = allocate(re.packet_len = h.packet_len);
			fread(re.name, h.str_len, 1, fp);
			fread(re.packet, re.packet_len, 1, fp);
			return &re;
		}
	}
	return NULL;
}

