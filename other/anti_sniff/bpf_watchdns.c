#include "includes.h"
#include "anti_sniff.h"

void *recv_raw_frame(HDEV fd, int *len);
int make_ptr_str(char *address, char *returnHolder);

void * watch_all_dns(HDEV fd, int *len){

  int length=0;
  void *pkt;
  struct bpf_program setfilt;
  struct bpf_insn bf_default[] = {
    { 0x6, 0, 0, 0x00000044 },
  };

  struct bpf_insn bf_dns[] = {
          { 0x28, 0, 0, 0x0000000c },
          { 0x15, 0, 8, 0x00000800 },
          { 0x30, 0, 0, 0x00000017 },
          { 0x15, 0, 6, 0x00000011 },
          { 0x28, 0, 0, 0x00000014 },
          { 0x45, 4, 0, 0x00001fff },
          { 0xb1, 0, 0, 0x0000000e },
          { 0x48, 0, 0, 0x00000010 },
          { 0x15, 0, 1, 0x00000035 },
          { 0x6, 0, 0, 0x00000044 },
          { 0x6, 0, 0, 0x00000000 },
  };

  setfilt.bf_insns = bf_dns;
  setfilt.bf_len = sizeof(bf_dns) / sizeof(struct bpf_insn);

  if (ioctl(fd, BIOCSETF, &setfilt) == -1){
    fprintf(stderr, "failed to set bpf dns filter\n");
    exit(1);
  }

  for (;;){
    pkt = (char *)recv_raw_frame(fd, &length);
    if (length > 0)
      break;
  }

  setfilt.bf_insns = bf_default;
  setfilt.bf_len = sizeof(bf_default) / sizeof(struct bpf_insn);

  if (ioctl(fd, BIOCSETF, &setfilt) == -1){
    fprintf(stderr, "failed to reset bpf orig filter\n");
  }

  if (pkt){
    *len = length;
    return(pkt);
  } else {
    *len = -1;
    return(NULL);
  }

}

/* watch_dns_ptr examines DNS packets for Query types of PTR (has an IP
   address and is atempting to look up a name. It returns true if the IP
   address in the DNS packet matches the one handed to it. 

   A couple of caveat's... we only check one Query though you could be seeing
   a variable number of queries in one packet. This is not seen too often
   in the wild and hell... this is beta code. .mudge */

int watch_dns_ptr(char *pkt, int len, char *ip_match){
  HEADER dns_h;
  unsigned int dns_offset, rr_offset, rr_size;
  unsigned int count, questionEntries;
  unsigned char *indx;
  unsigned char nameStr[MAX_LEN];
  unsigned char matchPTR[32];
#ifdef DEBUG
  unsigned int i;
#endif
  unsigned int min_str_len;

  memset(nameStr, '\0', sizeof(nameStr));

  if (!make_ptr_str(ip_match, matchPTR)){
    fprintf(stderr, "error making ptr lookup address\n");
    return FALSE;
  }
#ifdef DEBUG 
  printf("match string : %s\nPTR record created : %s\n", ip_match, matchPTR);
#endif 

  dns_offset = SIZE_ETHER_H + SIZE_IP_H + SIZE_UDP_H;
  rr_offset = dns_offset + SIZE_DNS_H;

/*
  if (len < SIZE_ETHER_H + SIZE_IP_H + SIZE_UDP_H + SIZE_DNS_H)
    return FALSE;
*/
  if (len < 50 )
    return FALSE;
 
  rr_size = len - rr_offset;

  memcpy(&dns_h, (char *)(pkt + dns_offset), sizeof(HEADER));

#ifdef DEBUG
  printf("dns id = %d\n", ntohs(dns_h.id));
  /* third byte */
  printf("response flag = %d\n", dns_h.qr);
  printf("opcode = %d\n", dns_h.opcode);
  printf("authoritative answer = %d\n", dns_h.aa);
  printf("truncated msg = %d\n", dns_h.tc);
  printf("recursion desired = %d\n", dns_h.rd);
  /* fourth byte */
  printf("recursion avail = %d\n", dns_h.ra);
#if defined(SOLARIS)
  printf("primary server required = %d\n", dns_h.pr);
#endif
  printf("unused = %d\n", dns_h.unused);
  printf("response code = %d\n", dns_h.rcode);

  printf("question entries = %d\n", ntohs(dns_h.qdcount));
  printf("answer entries = %d\n", ntohs(dns_h.ancount));
  printf("authority entries = %d\n", ntohs(dns_h.nscount));
  printf("resource entries = %d\n", ntohs(dns_h.arcount));
#endif

  /* questionEntries = ntohs(dns_h.qdcount); */
  questionEntries = dns_h.qdcount;
  
  /* we are only interested in querires on the bogus IP address that
     we sent out */
  if (!questionEntries)
    return FALSE;
  indx = (char *)(pkt + rr_offset);
  count = (unsigned int)(*indx);
#ifdef DEBUG
  printf("count was: %d\n", count);
#endif

  while (count){
    indx++;
    if (strlen(nameStr) + count < (MAX_LEN - 1)){
      strncat(nameStr, indx, count);
      indx += count;
      count = *indx;
      strncat(nameStr, ".", sizeof(nameStr) - strlen(nameStr));
    } else {
      fprintf(stderr, "Alert! someone is attempting to send LONG DNS packets\n");
      count = 0;
    }
  }
  nameStr[strlen(nameStr)-1] = '\0';
    
#ifdef DEBUG
  printf("NameStr = %s len: %d\n", nameStr, strlen(nameStr));
  printf("matchPTR = %s len: %d\n", matchPTR, strlen(nameStr));
#endif

#ifdef DEBUG
  indx = (char *)(pkt + dns_offset);
  for (i=0; i < SIZE_DNS_H + rr_size ; i++){
    if ((i % 12) == 0 )
      printf("\n");
    printf("0x%02x ", (indx[i] & 0xff));
  }
#endif

  min_str_len = (strlen(matchPTR) < strlen(nameStr)) ? strlen(matchPTR) : strlen(nameStr);

  if (strncmp(nameStr, matchPTR, min_str_len) == 0){
#ifdef DEBUG
    printf("THEY MATCH!!!\n");
#endif
    return TRUE;
  }
 
  return FALSE;
}

int make_ptr_str(char *address, char *returnHolder){
  char *ptr1, *ptr2, *ptr3, *ptr4; 
  char holder[MAX_LEN];
  int dot_cnt=0, i;

  strncpy(holder, address, MAX_LEN);

  for (i=0 ; i < strlen(holder); i++){
    if (holder[i] == '.')
      dot_cnt++;
  }
#ifdef DEBUG
  printf("dot count is : %d\n", dot_cnt);
#endif

  if (dot_cnt != 3)
    return FALSE;

  ptr1 = strtok(holder, ".");
  ptr2 = strtok((char *)NULL, ".");
  ptr3 = strtok((char *)NULL, ".");
  ptr4 = strtok((char *)NULL, ".");

#ifdef SOLARIS25
  sprintf(returnHolder, "%.3s.%.3s.%.3s.%.3s.in-addr.arpa", ptr4, ptr3,
          ptr2, ptr1);
#else
  snprintf(returnHolder, MAX_LEN, "%s.%s.%s.%s.in-addr.arpa", ptr4,
           ptr3, ptr2, ptr1);
#endif

  return TRUE;
}
