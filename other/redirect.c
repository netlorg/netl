/*  Telnet redirector
 *   By Alhambra (alhambra@infonexus.com)
 *    Feb 11, 1995 release .9
 *    Usage:
 *            redirector -p localport [-h remotehost] [-r remoteport]
 *            ie: 
 *            redirector -p 4300
 *            redirector -p 4400 -h whitehouse.gov -r 25
 *
 *   Should be fairly portable...to compile on:
 *   Solaris: gcc redirector.c -lsocket -lnsl -o redirector
 *   Linux:   gcc redirector.c -DLINUX -o redirector
 *   Irix:    gcc redirector.c -o redirector
 *
 *  I've tested this program on the above 3 OS's.  Porting to BSD based systems should be
 *  trivial( make the memsets into bzero's, etc)
 *
 *
 *    The idea behind this program is to be able to set up a redirector on some system, and be
 *    able to redirect your sessions through it.  For instance:
 *
 *    On host A, I run the redirector on port 4000:
 *    A:~ > redirector -p 4000
 *
 *    I'm on host B, and I want to go to host C.  SO I telnet to host A, port 4000
 *    B:~ > telnet A 4000
 *
 *    I'll be greeted with the following:
 *    Enter host:
 *
 *    Where I'll type 'C'
 *    Then I'll be asked:
 *    Enter port:
 *
 *    We're I'll enter 23 (telnet).
 *    And I'll be connected to host C.  Currently, the program doesn't support
 *    entering  a service name instead of a port number.  Oops.  I forgot.  
 *    SHould be *very* easy to add.  
 *    THis program is still in need of major cleaning up.  I runs fine, it's
 *    just ugly as sin.
 *    
 *    I'd like to see a series of redirectors go up.  I think it'd be cool to be able to telnet
 *    around the world, just to get back to your own machine.  And if you can't see the possible
 *    uses of such a chain...oh well.
 *
 *    Other ideas for usage:
 *            replacment for sendmail on network machines.  Set up redirector on port 25, and
 *            redirect it to the place you'd like mail delivered.
 *
 *            run httpd on unpriveledged port.  SInce redirector is much smaller, run it
 *            on port 80, and have it redirect all requests to an httpd running as a normal
 *            user on a higher port.
 *
 *    Plans for redirector:
 *            I've been thinking of implementing some form of encryption between redirectors. So,
 *    one could theoretically run a redirecotr on their localhost, and on another machine, and go
 *    through thier local redirecotr, and out to the other redirector, and encrypt between the
 *    two.  It's an interesting possibilty, and anyone who is interested in undertaking such
 *    a project along with me, please let me know.
 *
 */

#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/syslog.h>
#include <sys/param.h>
#include <sys/times.h>
#ifdef LINUX
#include <sys/time.h>
#endif
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/signal.h>
#include <arpa/inet.h>
#include <netdb.h>

extern int errno;

void
usage (char *progname)
{
  fprintf (stderr, "%s: -p LOCALPORT -h REMOTEHOST -r REMOTEPORT\n", progname);
  fprintf (stderr, "example:  %s -p 9100 -h foo.bar.com -r 25\n", progname);
  fflush (stderr);
  exit (1);
}



int
set_fl (int fd, int flags)
{				/* set file descriptor props */
  int val;
  if ((val = fcntl (fd, F_GETFL, 0)) < 0)
    return (-1);
  val |= flags;
  if ((fcntl (fd, F_SETFL, val)) < 0)
    return (-1);
  return (0);
}


setup_socket (int *tcpsocket, short port)
{				/* set up incoming socket */

  struct sockaddr_in serv_addr;

  if ((*tcpsocket = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      exit (-1);
    }

  memset (&serv_addr, 0, sizeof (serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
  serv_addr.sin_port = htons (port);
  setsockopt(*tcpsocket,SOL_SOCKET,SO_REUSEADDR,0,0);
  setsockopt(*tcpsocket,SOL_SOCKET,SO_LINGER,0,0);
  if (bind (*tcpsocket, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    return (-1);

  

  return (0);
}



void
feed_through (int tcpfd, int outfd)
{

  fd_set fdvar;
  char buffer[8192];
  int width;
  size_t numbytes;

  width = (tcpfd > outfd) ? tcpfd + 1 : outfd + 1;
  /* Flush the input buffer on the serial side */
  set_fl (outfd, O_NONBLOCK);
  while ((read (outfd, buffer, sizeof (buffer))) > 0)
    fprintf (stderr, "ERROR!\n");

  while (1)
    {
      FD_ZERO (&fdvar);
      FD_SET (tcpfd, &fdvar);
      FD_SET (outfd, &fdvar);


      select (width, &fdvar, (fd_set *) 0, (fd_set *) 0, NULL);
      if (FD_ISSET (tcpfd, &fdvar))
	{

	  if ((numbytes = read (tcpfd, buffer, sizeof (buffer))) == 0)
	    return;
	  if ((write (outfd, buffer, numbytes)) != numbytes)
	    {
	      exit (-1);
	    }
	}
      else if (FD_ISSET (outfd, &fdvar))
	{
	  /* Read from the outfd and write to the tcp */
	  if ((numbytes = read (outfd, buffer, sizeof (buffer))) == 0)
	    return;
	  if ((write (tcpfd, buffer, numbytes)) != numbytes)
	    {
	      exit (-1);
	    }
	}
      else
	{
	  exit (-1);
	}
    }
}


main (int argc, char *argv[])
{
  int c;
  extern char *optarg;
  extern int optind;
  int pset = 0, sset = 0, dset = 0, hset = 0;
  int port, remote, x, y;
  speed_t speed;
  char *host, buffer[1024], hosta[1024];
  struct hostent *nametocheck;
  int outfd, tcpfd;
  int client_len, tcpsocket, outsocket, serv_len, len;
  struct sockaddr_in client_addr;
  struct sockaddr_in serv_addr;
  struct in_addr outgoing;
  pid_t pid, pid2;


  while ((c = getopt (argc, argv, "p:r:h:")) != -1)
    switch (c)
      {
      case 'p':
	port = atoi (optarg);
	pset = 1;
	break;
      case 'r':
	remote = atoi (optarg);
	dset = 1;
	break;
      case 'h':
	host = optarg;
	hset = 1;
	break;
      case '?':
	usage (argv[0]);
	break;
      }



  /* Okay, now, let's daemonize outselves */

  signal (SIGTTOU, SIG_IGN);
  signal (SIGTTIN, SIG_IGN);
  signal (SIGTSTP, SIG_IGN);

  if ((c = fork ()) < 0)
    fprintf (stderr, "Can't fork. \n");
  else if (c > 0)
    exit (0);

  if (setpgrp () == -1)
    fprintf (stderr, "Can't change process group");

  if ((outfd = open ("/dev/tty", O_RDWR)) >= 0)
    {
      ioctl (outfd, TIOCNOTTY, (char *) NULL);
      close (outfd);
    }

  for (c = 0; c < NOFILE; c++)
    close (c);

  errno = 0;
  chdir ("/");
  umask (0);


  /* Bind the specified port. */
  if (setup_socket (&tcpsocket, port) == -1)
    {
      fprintf (stderr, "Error in seting up the socket. Aborting.\n");
      exit (-1);
    }


  listen (tcpsocket, 5);


  /* We wait for a connection on the spec. port */



  for (;;)
    {
      client_len = sizeof (client_addr);
      tcpfd = accept (tcpsocket, (struct sockaddr *) &client_addr, &client_len);

      outsocket = socket (AF_INET, SOCK_STREAM, 0);
      memset (&serv_addr, 0, sizeof (serv_addr));
      serv_addr.sin_family = AF_INET;

      /* Fork here.... */
      if ((pid = fork ()) < 0)
	{
	  fprintf (stderr, "Fork Error!");
	  exit (-1);
	}


      if (pid == 0)
	{			/* Fork again, to eliminate zombies */
	  if ((pid2 = fork ()) < 0)
	    {
	      exit (-1);
	    }
	  if (pid2 == 0)
	    {close(tcpsocket);
	      if (hset != 1)	/* if remote host isn't spec'd on the cmd line... */
		{
		  alarm (60);
		  x = 0;
		  write (tcpfd, "Enter host: ", 12);
		  len = read (tcpfd, buffer, 1);
		  while (buffer[0] != '\n')
		    {

		      hosta[x] = buffer[0];
		      x++;
		      if (x > 8192)
			break;	/* if the host name is this long, something is not right... */
		      len = read (tcpfd, buffer, 1);
		    }

		  host = (char *) malloc (sizeof (char) * x - 2);
		  for (y = 0; y < x - 1; y++)
		    host[y] = hosta[y];

		  alarm (0);
		}
	      if (dset != 1)	/* If port isn't spec'd on the cmd line... */
		{
		  alarm (60);
		  write (tcpfd, "Enter port: ", 12);
		  len = read (tcpfd, buffer, 100);
		  remote = atoi (buffer);
		  
		  alarm (0);
		}
	      /* Get our host name */
	      nametocheck = gethostbyname (host);

	      /* Ugly stuff to get host name into inet_ntoa form */
	      (void *) memcpy (&outgoing.s_addr, nametocheck->h_addr_list[0],
			       sizeof (outgoing.s_addr));


	      strcpy (host, inet_ntoa (outgoing));
	      serv_addr.sin_addr.s_addr = inet_addr (host);
	      serv_addr.sin_port = htons (remote);
		alarm(120);
	      connect (outsocket, (struct sockaddr *) &serv_addr, sizeof (serv_addr));
		alarm(0);
	      feed_through (tcpfd, outsocket);	/* connect the two sockets, and go! */
	      close (outsocket);
	      close (tcpfd);
	      exit (0);
	    }
	  exit ();
	}




      wait (NULL);		/* Wait for kid 1 to exit... */
      close (tcpfd);
      close (outsocket);


    }
  close (tcpsocket);
  return 0;
}
