#include "includes.h"
#include "anti_sniff.h"

void *recv_raw_frame(HDEV fd, int *len);

void * watch_all_arpresp(HDEV fd, int *len){
 
  int length=0;
  void *pkt = NULL;
  struct bpf_program setfilt;
  struct bpf_insn bf_default[] = {
    { 0x6, 0, 0, 0x00000044 },
  };

  struct bpf_insn bf_arp[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 3, 0x00000806 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x15, 0, 1, 0x00000002 },
        { 0x6, 0, 0, 0x00000044 },
        { 0x6, 0, 0, 0x00000000 },
  };


  setfilt.bf_insns = bf_arp;
  setfilt.bf_len = sizeof(bf_arp) / sizeof(struct bpf_insn);

  if (ioctl(fd, BIOCSETF, &setfilt) == -1){
    fprintf(stderr, "failed to set bpf arp filter\n");
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

