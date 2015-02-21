#include "includes.h"
#include "anti_sniff.h"

void usage(char *);
int run_etherpingtest(char *targetIP, char *etherADDR, 
                      struct result *resultStruct);
int run_icmptimetest(int test, char *targetIP, int num_pkts, 
                     struct result *res);
int run_dnstest(char *targetIP, struct result *res);
int run_echotest(int test, char *targetIP, int num_pkts, 
                 struct result *res);
void printResultStruct(struct result *r);
void initResult(struct result *);
void massageResult(struct result *, char *);
int validTarget(char *);
int run_arptest(char *target, struct result *resStruct);


int main(int argc, char *argv[]){
  struct result resultStruct;
  int ch, i;
  int dnstest=0, icmptimetest=0, etherpingtest=0, targetflag=0, etherflag=0;
  int echotest=0, winpingtest=0, arptest=0;
  int num_pkts_flag=0, num_pkts=0, num_tests=0;
  int flag66=0, flag3way=0, flagtcpsyn=0, flood_type_flag=0;
  char *options, *value;
  char *targetIP = NULL, *etherADDR = NULL;
  char defaultEth[] = "66:66:66:66:66:66";
  char *myopts[] = { "SIXTYSIX", "TCPSYN", "THREEWAY", NULL};

  while ((ch = getopt(argc, argv, "123456t:e:n:f:")) != -1){
    switch(ch) {
      case '1':
        dnstest++;
        num_tests++;
        break;
      case '2':
        icmptimetest++;
        num_tests++;
        break;
      case '3':
        etherpingtest++;
        num_tests++;
        break;
      case '4':
        winpingtest++;
        num_tests++;
        break;
      case '5':
        echotest++;
        num_tests++;
        break;
      case '6':
        arptest++;
        num_tests++;
        break;
      case 't':
        targetflag++;
        targetIP = optarg;
        break;
      case 'e':
        etherflag++;
        etherADDR = optarg;
        break;
      case 'n':
        num_pkts_flag++;
        num_pkts = atoi(optarg);
        break;
      case 'f':
        flood_type_flag++;
        options = optarg;
        while (*options != '\0') {
          switch(getsubopt(&options, myopts, &value)) {
            case SIXTYSIX :
              flag66++;
              break;
            case THREEWAY:
              flag3way++;
              break;
            case TCPSYN:
              flagtcpsyn++;
              break;
            default:
              printf("unknown suboption\n");
              usage(argv[0]);
          }
        } 
        break;
      default:
        usage(argv[0]);
    }
  }

  if (!etherflag)
    etherADDR = defaultEth;

  if (!num_pkts)
    num_pkts = 10;

  if (num_tests > 1){
    printf("please only specify one test at a time\n");
    usage(argv[0]);
  }

  if (!num_tests){
    printf("must choose at least one test to run!\n");
    usage(argv[0]);
  }

  if (((etherpingtest) || (icmptimetest) || (dnstest) || (echotest) ||
       (winpingtest) || (arptest) ) && (!targetflag)){
    printf("target required\n");
    usage(argv[0]);
  }

  if ((winpingtest) && (etherflag)){
    printf("specifying an ether address can potentially negate this test...\n");
    printf("hope you know what you're doing...\n");
  }

  if (!flood_type_flag){
    /* do all types */
    flag66++;
    flag3way++;
    flagtcpsyn++;
  } else if ( (!flag66) && (!flag3way) && (!flagtcpsyn) ){
    printf("flood type flag requires an argument\n");
    usage(argv[0]);
  } 

  if (etherpingtest){

    if (validTarget(targetIP) == FALSE){
      printf("%s does not appear to be in the local net range!!\n", targetIP);
      printf("There is a good chance this test will be innefectual.\n");
      printf("Type <ctrl>-c to quit now or wait to run the test anyway...\n");
      for (i=0; i < 5; i++){
        printf(".");
        fflush(NULL);
        sleep(1);
      }
      printf("\n");
      /* go on ahead with things */
    }

    initResult(&resultStruct);
    run_etherpingtest(targetIP, etherADDR, &resultStruct);
    massageResult(&resultStruct, targetIP);
    printResultStruct(&resultStruct);
  } 

  if (winpingtest){

    if (validTarget(targetIP) == FALSE){
      printf("%s does not appear to be in the local net range!!\n", targetIP);
      printf("There is a good chance this test will be innefectual.\n");
      printf("Type <ctrl>-c to quit now or wait to run the test anyway...\n");
      for (i=0; i < 5; i++){
        printf(".");
        fflush(NULL);
        sleep(1);
      }
      printf("\n");
      /* go on ahead with things */
    }

    initResult(&resultStruct);
    if (etherflag)
      run_etherpingtest(targetIP, etherADDR, &resultStruct);
    else
      run_etherpingtest(targetIP, "ff:ff:ff:ff:ff:00", &resultStruct);
    massageResult(&resultStruct, targetIP);
    printResultStruct(&resultStruct);
  }

  if (icmptimetest){

    if (validTarget(targetIP) == FALSE){
      printf("%s does not appear to be in the local net range!!\n", targetIP);
      printf("There is a good chance this test will be innefectual.\n");
      printf("Type <ctrl>-c to quit now or wait to run the test anyway...\n");
      for (i=0; i < 5; i++){
        printf(".");
        fflush(NULL);
        sleep(1);
      }
      printf("\n");
      /* go on ahead with things */
    }
      
    if (flag66){
      initResult(&resultStruct);
      run_icmptimetest(SIXTYSIX, targetIP, num_pkts, &resultStruct);
      massageResult(&resultStruct, targetIP);
      printResultStruct(&resultStruct);
    }

    if (flagtcpsyn){
      initResult(&resultStruct);
      run_icmptimetest(TCPSYN, targetIP, num_pkts, &resultStruct);
      massageResult(&resultStruct, targetIP);
      printResultStruct(&resultStruct);
    }

    if (flag3way){
      initResult(&resultStruct);
      run_icmptimetest(THREEWAY, targetIP, num_pkts, &resultStruct);
      massageResult(&resultStruct, targetIP);
      printResultStruct(&resultStruct);
    }
  }  

  if (echotest){

    if (validTarget(targetIP) == FALSE){
      printf("%s does not appear to be in the local net range!!\n", targetIP);
      printf("There is a good chance this test will be innefectual.\n");
      printf("Type <ctrl>-c to quit now or wait to run the test anyway...\n");
      for (i=0; i < 5; i++){
        printf(".");
        fflush(NULL);
        sleep(1);
      }
      printf("\n");
      /* go on ahead with things */
    }

    if (flag66){
      initResult(&resultStruct);
      run_echotest(SIXTYSIX, targetIP, num_pkts, &resultStruct);
      massageResult(&resultStruct, targetIP);
      printResultStruct(&resultStruct);
    }

    if (flagtcpsyn){
      initResult(&resultStruct);
      run_echotest(TCPSYN, targetIP, num_pkts, &resultStruct);
      massageResult(&resultStruct, targetIP);
      printResultStruct(&resultStruct);
    }

    if (flag3way){
      initResult(&resultStruct);
      run_echotest(THREEWAY, targetIP, num_pkts, &resultStruct);
      massageResult(&resultStruct, targetIP);
      printResultStruct(&resultStruct);
    }
  }

  if (dnstest){
    initResult(&resultStruct);
    run_dnstest(targetIP, &resultStruct);
    massageResult(&resultStruct, targetIP);
    printResultStruct(&resultStruct);
  }

  if (arptest){
    initResult(&resultStruct);
    run_arptest(targetIP, &resultStruct);
    massageResult(&resultStruct, targetIP);
    printResultStruct(&resultStruct);
  }

  exit(0);
}

void usage(char *progname){
  char *ptr;

  ptr = strrchr(progname, '/');
  if (!ptr)
    ptr = progname;
  else
    ptr++;

  printf("AntiSniff Researchers version 1-1-2\n");
  printf("Usage: %s -1|2|3|5|6 [-t target -n pkts -e ether -f opts]\n", ptr);
  printf("  by mudge@l0pht.com\n");
  printf("  -1  Enable DNS test (requires -t)\n");
  printf("  -2  Enable ICMP time delta test (requires -t, optional -n)\n");
  printf("  -3  Enable Ether Ping test (requires -t, optional -e)\n");
  printf("  -4  Enable NT EtherPing test (requires -t)\n");
  printf("  -5  Enable UDP Echo test (requires -t, optional -n)\n");
  printf("  -6  Enable multicast arp test (requires -t)\n");
  printf("  -t  target IP address\n");
  printf("  -e  target ether addr for raw frame\n");
  printf("  -n  number of packets to send (optional)\n");
  printf("  -f TCPSYN,SIXTYSIX,THREEWAY for -2 and -5 this defines the flood");
  printf("traffic that\n      will be generated (optional, defaults"); 
  printf("running all three flood types)\n");
  exit(1);
}

