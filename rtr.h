#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include "termios.h"
#include "string.h"
//Maximum number of IP instances expected to be read by default
#define MAX_READ_LENGTH 10
//Expected maximum read of characters from file line
#define FILE_MAX_READ 1024
//Delimeter to determine various parameters
#define DELIM_CHAR '&'

class helperz{
public:
  char *IPv4 = (char *)calloc('\0', 16);
  char *IPv6 = (char *)calloc('\0', 64);
  FILE *fil;
  helperz(){
    char *line = (char *)malloc(64);
    for(char b = 0; b < 2; b++){
      this->fil = fopen((b?"ip6.txt":"ip4.txt"), "r");
      fgets((char *)line, 64, this->fil);
      line[strlen((char *)line)-1] = '\0';
      strcpy((b?this->IPv6:this->IPv4), line);
    }
  }
};

class getData{
private:
  //Helperz object
  helperz *H = new helperz();
  //Directional data on data flows
  struct directions{
    //0=Ingress, 1=Egress
    bool direcc = 0;
    //0=TCP, 1=UDP
    bool tu = 1;
    //0=IPv4, 1=IPv6
    bool ip_v = 1;
    //0=ICMPv6, 1=ARP
    bool ia[2] = {0, 1};
    //Protocol used
    char *proto = (char *)calloc('\0', 32);
    //Source IPv4
    char *src = (char *)calloc('\0', 16);
    //Destination IPv4
    char *dst = (char *)calloc('\0', 16);
    //Source IPv6
    char *src_6 = (char *)calloc('\0', 64);
    //Destination IPv6
    char *dst_6 = (char *)calloc('\0', 64);
    //TCP source port
    char *s_port = (char *)calloc('\0', 8);
    //TCP destination port
    char *d_port = (char *)calloc('\0', 8);
    //TCP source port
    char *u_s_port = (char *)calloc('\0', 8);
    //TCP destination port
    char *u_d_port = (char *)calloc('\0', 8);
    //Source MAC addr
    char *s_eth = (char *)calloc('\0', 24);
    //Destination MAC addr
    char *d_eth = (char *)calloc('\0', 24);
    //Resolved source MAC
    char *s_eth_res = (char *)calloc('\0', 32);
    //Resolved destination MAC
    char *d_eth_res = (char *)calloc('\0', 32);
    //Resolved HW source
    char *s_eth_res_oui = (char *)calloc('\0', 32);
    //Resolved HW destination
    char *d_eth_res_oui = (char *)calloc('\0', 32);
    //ICMPv6 DNS specified
    char *rdns = (char *)calloc('\0', 64);
    //ICMPv6 src
    char *i_src_6 = (char *)calloc('\0', 64);
    //ICMPv6 dst
    char *i_dst_6 = (char *)calloc('\0', 64);
    //ARP ip src
    char *a_src = (char *)calloc('\0', 16);
    //ARP ip dst
    char *a_dst = (char *)calloc('\0', 16);
    //ARP src MAC
    char *s_a_eth = (char *)calloc('\0', 64);
    //ARP dst MAC
    char *d_a_eth = (char *)calloc('\0', 64);
    //WHOAMI search
    char *wai_srch_s = (char *)calloc('\0', 16);
    //DOG search
    char *dns_name_s = (char *)calloc('\0', 32);
    //WHOAMI search
    char *wai_srch_d = (char *)calloc('\0', 16);
    //DOG search
    char *dns_name_d = (char *)calloc('\0', 32);
  }dr;
  //Information that is necessary
  struct informational_variables{
    //Max length of file name is 24
    FILE *fil;
    //IPs
    std::vector<getData::directions> *ips = new std::vector<getData::directions>(MAX_READ_LENGTH);
    //Index of IPs
    unsigned char ipx = 0;
  }iv;
  //String for incoming text from file

  //Full collection of info
  //void collection();
  //Get info specified in_c_str, displaying direction (0=Ingress, 1=Egress),
  //  Along with using binary tree to find how and where to store new info.
  void getInfo(char *in_c_str, bool direction, char);
  //Initialize each directions object in ips vector
  void intDirc();
  //Queries for resolution; 0=SRC, 1=DST
  void ipQuery(char *ip_to_search, bool side_of_flow);
public:
  //Full collection of info
  void collection();
  //Constructor using the file name
  getData(char *f){
    this->iv.fil = fopen(f, "r");
  }
  //Print all data gathered
  void printData();
  //Print newfound data!
  void printInfo();
  //Full data output
  void verboInfo(char *index_of_flow);
};
