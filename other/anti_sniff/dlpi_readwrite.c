#include "includes.h"
#include "anti_sniff.h"

int putmsg(int, const struct strbuf *, const struct strbuf *, int);
void bzero(void *s, size_t n);
int getmsg(int, struct strbuf *, struct strbuf *, int *);
int dlattachreq(int, u_long);
int dlokack(int, char *);
void dlpromisconreq(int, u_long);
void dlbindreq(int, u_long, u_long, u_long, u_long, u_long);
void dlbindack(int, char *);
int strioctl(int, int, int, int, char *);


int send_raw_frame(HDEV fd, void *buff, int len, int flags){
  struct strbuf dbuf, *dp = &dbuf;

  dp->buf = buff;
  dp->len = len;
  dp->maxlen = dp->len;

  if (putmsg(fd, NULL, dp, 0) == -1) {
#ifdef DEBUG
    perror("putmsg");
#endif
    return FALSE;
  }
  if (ioctl(fd, I_FLUSH, FLUSHW) == -1) {
#ifdef DEBUG
    perror("I_FLUSHW");
#endif
    return FALSE;
  }
  return TRUE;
}

void * recv_raw_frame(HDEV fd, int *len){
/*
  u_char *databuf; 
  struct strbuf *data;
*/
  u_char databuf[MAXDLBUF];
  struct strbuf data;
  int ret, flags;

/*
  databuf = (char *)memalign(SIZE_U_LONG, MAXDLBUF); 
  data = (struct strbuf *)memalign(SIZE_U_LONG, sizeof(struct strbuf));
*/

/*
  bzero(databuf, MAXDLBUF);
  data->buf = (char *) databuf;
  data->maxlen = MAXDLBUF;
  data->len = 0;
*/
  bzero(&databuf, MAXDLBUF);
  data.buf = databuf;
  data.maxlen = MAXDLBUF;
  data.len = 0;

/*
  ret = getmsg(fd, (struct strbuf *)NULL, data, &flags);
*/
  ret = getmsg(fd, (struct strbuf *)NULL, &data, &flags);

  if (ret < 0){
    *len = -1;
    return((void *)NULL);
  }

/*
  *len = data->len;
  return ((void *)data->buf);
*/
  *len = data.len;
  return ((void *)data.buf);
}
    
HDEV open_net_intf(int value){

  char *device;
  char devname[16], *s, buf[256];
  int i, fd;
  char *intName, *intPtr;
  
  intName = getenv(ANTI_INTERFACE);
  if (!intName){
#ifdef SOLARIS25
    (void) sprintf(devname, "/dev/%.10s", DEVICENAME);
#else
    (void) snprintf(devname, sizeof(devname), "/dev/%s", DEVICENAME);
#endif
  } else {
    intPtr = strrchr(intName, '/');
    if (intPtr)
      device = ++intPtr;
    else
      device = intName;
#ifdef SOLARIS25
    (void) sprintf(devname, "/dev/%.10s", device);
#else
    (void) snprintf(devname, sizeof(devname), "/dev/%s", device);
#endif
  }

  s = devname + 5;
  while (*s && !isdigit(*s))
    s++;
  if (!*s) {
    fprintf(stderr, "bad device name %s\n", devname);
    exit(-1);
  }
  i = atoi(s);
  *s = '\0';
 /*
  * For writing
  */
  if ((fd = open(devname, O_RDWR)) < 0) {
    fprintf(stderr, "O_RDWR(1) ");
    perror(devname);
    exit(-1);
  }

 
/*
  if (dlattachreq(fd, i) == -1 || dlokack(fd, buf) == -1) {
    fprintf(stderr, "DLPI error\n");
    exit(-1);
  }
    Currently dlattachreq and dlokack exit if unsuccesfull - so all
    we do right now is call them. They should be changed to comply to
    returning TRUE||FALSE  .mudge 
*/
  dlattachreq(fd, i);
  dlokack(fd, buf);

  dlpromisconreq(fd, DL_PROMISC_PHYS);
  dlokack(fd, buf);

  dlbindreq(fd, ETHERTYPE_IP, 0, DL_CLDLS, 0, 0);
  dlbindack(fd, buf);

 /*
  * write full headers
  */
  if (strioctl(fd, DLIOCRAW, -1, 0, NULL) == -1) {
    fprintf(stderr, "DLIOCRAW error\n");
    exit(-1);
  }
  return fd;
}

