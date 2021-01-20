#include "rtr.h"

void getData::collection(){
  //String used to get input, comma location for CSV, latest value for CSV item
  char *line = (char *)malloc(FILE_MAX_READ), *inpt = (char *)calloc('\0', 128), lv = 0;
  unsigned char com = 0;

  if(this->iv.fil == NULL){
    std::printf("ERROR::File does not exist!\n");
  }
  while(!feof(this->iv.fil) && this->iv.ipx < MAX_READ_LENGTH){
    for(char i = strlen(inpt)-1; i >= 0; i++) inpt[i] = '\0';
    for(char i = strlen(line)-1; i >= 0; i++) line[i] = '\0';
    fgets((char *)line, FILE_MAX_READ, this->iv.fil);
    line[strlen((char *)line)] = '\0';
    lv = 0;
    com = 0;
    this->intDirc();

    //std::printf("%d:%s\n", strlen((char *)line), line);
    for(short unsigned int i = 0; i < strlen((char *)line); i++){
      //std::printf("INDX::%c\n", line[i]);
      inpt[lv++] = (line[i] == DELIM_CHAR ? '\0':line[i]);
      //std::printf("\t=>%c-%c %d: %s %d %c\n", line[i], inpt[lv], inpt[lv], inpt, strlen((char *)line), line[strlen((char *)line)-1]);

      if(line[i] == DELIM_CHAR || i == strlen((char *)line)-1){
        //std::printf("NEXT\n");
        lv = 0;
        //DST is even num, SRC is odd.

        this->getInfo((char *)inpt, (com++%2), com);
      }
    }

    if(com == 20) this->iv.ipx++;
  }
}

void getData::intDirc(){
  //0=Ingress, 1=Egress
  this->iv.ips->at(this->iv.ipx).direcc = 0;
  //0=TCP, 1=UDP
  this->iv.ips->at(this->iv.ipx).tu = 1;
  //0=IPv4, 1=IPv6
  this->iv.ips->at(this->iv.ipx).ip_v = 1;
  //0=ICMPv6, 1=ARP
  this->iv.ips->at(this->iv.ipx).ia[0] = 0;
  this->iv.ips->at(this->iv.ipx).ia[1] = 1;
  //Protocol used
  this->iv.ips->at(this->iv.ipx).proto[0] = '\0';
  //Source IPv4
  this->iv.ips->at(this->iv.ipx).src[0] = '\0';
  //Destination IPv4
  this->iv.ips->at(this->iv.ipx).dst[0] = '\0';
  //Source IPv6
  this->iv.ips->at(this->iv.ipx).src_6[0] = '\0';
  //Destination IPv6
  this->iv.ips->at(this->iv.ipx).dst_6[0] = '\0';
  //TCP source port
  this->iv.ips->at(this->iv.ipx).s_port[0] = '\0';
  //TCP destination port
  this->iv.ips->at(this->iv.ipx).d_port[0] = '\0';
  //TCP source port
  this->iv.ips->at(this->iv.ipx).u_s_port[0] = '\0';
  //TCP destination port
  this->iv.ips->at(this->iv.ipx).u_d_port[0] = '\0';
  //Source MAC addr
  this->iv.ips->at(this->iv.ipx).s_eth[0] = '\0';
  //Destination MAC addr
  this->iv.ips->at(this->iv.ipx).d_eth[0] = '\0';
  //Resolved source MAC
  this->iv.ips->at(this->iv.ipx).s_eth_res[0] = '\0';
  //Resolved destination MAC
  this->iv.ips->at(this->iv.ipx).d_eth_res[0] = '\0';
  //Resolved HW source
  this->iv.ips->at(this->iv.ipx).s_eth_res_oui[0] = '\0';
  //Resolved HW destination
  this->iv.ips->at(this->iv.ipx).d_eth_res_oui[0] = '\0';
  //ICMPv6 DNS specified
  this->iv.ips->at(this->iv.ipx).rdns[0] = '\0';
  //Source IPv6
  this->iv.ips->at(this->iv.ipx).i_src_6[0] = '\0';
  //Destination IPv6
  this->iv.ips->at(this->iv.ipx).i_dst_6[0] = '\0';
  //ARP ip src
  this->iv.ips->at(this->iv.ipx).a_src[0] = '\0';
  //ARP ip dst
  this->iv.ips->at(this->iv.ipx).a_dst[0] = '\0';
  //ARP src MAC
  this->iv.ips->at(this->iv.ipx).s_a_eth[0] = '\0';
  //ARP dst MAC
  this->iv.ips->at(this->iv.ipx).d_a_eth[0] = '\0';
  //DNS search
  this->iv.ips->at(this->iv.ipx).dns_name_s[0] = '\0';
  //Whois search
  this->iv.ips->at(this->iv.ipx).wai_srch_s[0] = '\0';
  //DNS search
  this->iv.ips->at(this->iv.ipx).dns_name_d[0] = '\0';
  //Whois search
  this->iv.ips->at(this->iv.ipx).wai_srch_d[0] = '\0';
}

void getData::getInfo(char *in, bool d, char btv){
  switch(btv){
    case 0://proto
      strcpy(this->iv.ips->at(this->iv.ipx).proto, in);
      break;
    case 1://src
      if(in[0] > 0){
        this->iv.ips->at(this->iv.ipx).ip_v = 0;
        strcpy(this->iv.ips->at(this->iv.ipx).src, in);
        this->ipQuery(this->iv.ips->at(i).src, 0);
      }
      break;
    case 2://dst
      strcpy(this->iv.ips->at(this->iv.ipx).dst, in);
      if(in[0] > 0)this->ipQuery(this->iv.ips->at(i).dst, 1);
      break;
    case 3://s_port
      if((int)in[0] > 0) this->iv.ips->at(this->iv.ipx).tu = 0;
        strcpy(this->iv.ips->at(this->iv.ipx).s_port, in);
      break;
    case 4://d_port
      strcpy(this->iv.ips->at(this->iv.ipx).d_port, in);
      break;
    case 5://s_eth
      strcpy(this->iv.ips->at(this->iv.ipx).s_eth, in);
      break;
    case 6://d_eth
      strcpy(this->iv.ips->at(this->iv.ipx).d_eth, in);
      break;
    case 7://s_eth_res
      strcpy(this->iv.ips->at(this->iv.ipx).s_eth_res, in);
      break;
    case 8://d_eth_res
      strcpy(this->iv.ips->at(this->iv.ipx).d_eth_res, in);
      break;
    case 9://s_eth_res_oui
      strcpy(this->iv.ips->at(this->iv.ipx).s_eth_res_oui, in);
      break;
    case 10://d_eth_res_oui
      strcpy(this->iv.ips->at(this->iv.ipx).d_eth_res_oui, in);
      break;
    case 11://src_6
      strcpy(this->iv.ips->at(this->iv.ipx).src_6, in);
      if(in[0] > 0)this->ipQuery(this->iv.ips->at(i).src_6, 0);

      break;
    case 12://dst_6
      strcpy(this->iv.ips->at(this->iv.ipx).dst_6, in);
      if(in[0] > 0)this->ipQuery(this->iv.ips->at(i).dst_6, 1);

      break;
    case 13://u_s_port
      strcpy(this->iv.ips->at(this->iv.ipx).u_s_port, in);
      break;
    case 14://u_d_port
      strcpy(this->iv.ips->at(this->iv.ipx).u_d_port, in);
      break;
    case 15://rdns
      if(in[0] > 0){
        this->iv.ips->at(this->iv.ipx).ia[0] = 1;
        this->iv.ips->at(this->iv.ipx).ia[1] = 0;
      }
      strcpy(this->iv.ips->at(this->iv.ipx).rdns, in);
      break;
    case 16://a_src
      if(in[0] > 0){
        this->iv.ips->at(this->iv.ipx).ia[0] = 1;
        strcpy(this->iv.ips->at(this->iv.ipx).a_src, in);
        if(in[0] > 0)this->ipQuery(this->iv.ips->at(i).a_dst, 0);
      }
      break;
    case 17://a_dst
      strcpy(this->iv.ips->at(this->iv.ipx).a_dst, in);
      if(in[0] > 0)this->ipQuery(this->iv.ips->at(i).a_dst, 1);
      break;
    case 18://s_a_eth
      strcpy(this->iv.ips->at(this->iv.ipx).s_a_eth, in);
      break;
    case 19://d_a_eth
      strcpy(this->iv.ips->at(this->iv.ipx).d_a_eth, in);
      break;
    case 20:
      strcpy(this->iv.ips->at(this->iv.ipx).i_src_6, in);
      if(in[0] > 0)this->ipQuery(this->iv.ips->at(i).dst, 1);c
      break;
    case 21:
      strcpy(this->iv.ips->at(this->iv.ipx).i_dst_6, in);
      if(in[0] > 0)this->ipQuery(this->iv.ips->at(i).dst, 1);c
      break;
    }
}

void getData::printData(){
  std::printf("EF0\n");
  //String used to get input
  char inpt[120];
  if(this->iv.fil == NULL){
    std::printf("ERROR::File does not exist!\n");
  }
  while(!feof(this->iv.fil)){
    fgets(inpt, 120, this->iv.fil);
    std::printf("%s\n", inpt);
  }
  std::printf("EF1\n");
}

void getData::printInfo(){
  for(char i = 0; i < this->iv.ips->size(); i++){
    std::printf("[%d]", i);
    std::printf(" IPv%c ", (this->iv.ips->at(i).ip_v?'6':'4'));
    if(this->iv.ips->at(i).ia[0]){
      std::printf(" %s ", (this->iv.ips->at(i).ia[0]?(this->iv.ips->at(i).ia[1]?this->iv.ips->at(i).s_a_eth:this->iv.ips->at(i).i_src_6):(this->iv.ips->at(i).ip_v?this->iv.ips->at(i).src_6:this->iv.ips->at(i).src)));
    } else std::printf(" %s\t[%s]", ((!strcmp(this->H->IPv4, this->iv.ips->at(i).src)||!strcmp(this->H->IPv6, this->iv.ips->at(i).src_6))?(char *)"[HOST]":(this->iv.ips->at(i).ia[0]?(this->iv.ips->at(i).ia[1]?this->iv.ips->at(i).s_a_eth:this->iv.ips->at(i).i_src_6):(this->iv.ips->at(i).ip_v?this->iv.ips->at(i).src_6:this->iv.ips->at(i).src))), (this->iv.ips->at(i).tu?this->iv.ips->at(i).u_s_port:this->iv.ips->at(i).s_port));
    if(!(!strcmp(this->H->IPv4, this->iv.ips->at(i).src)||!strcmp(this->H->IPv6, this->iv.ips->at(i).src_6)))
      this->ipQuery(this->iv.ips->at(i).src, 0);
    std::printf("={%s}>", this->iv.ips->at(i).proto, this->iv.ips->at(i).dst, this->iv.ips->at(i).dst_6, this->iv.ips->at(i).d_port, this->iv.ips->at(i).u_d_port);
    if(this->iv.ips->at(i).ia[0] && this->iv.ips->at(i).ia[1]) std::printf("BROADCAST\n");
    else  std::printf(" %s[%s]", (this->iv.ips->at(i).ia[0]?(this->iv.ips->at(i).ia[1]?(this->iv.ips->at(i).ip_v?this->iv.ips->at(i).dst_6:this->iv.ips->at(i).dst):this->iv.ips->at(i).i_dst_6):(this->iv.ips->at(i).ip_v?this->iv.ips->at(i).dst_6:this->iv.ips->at(i).dst)), (this->iv.ips->at(i).tu?this->iv.ips->at(i).u_d_port:this->iv.ips->at(i).d_port));
    std::printf("%s\n", ((!strcmp(this->H->IPv4, this->iv.ips->at(i).dst)||!strcmp(this->H->IPv6, this->iv.ips->at(i).dst_6))?(char *)"[HOST]":""));
    if(!((!strcmp(this->H->IPv4, this->iv.ips->at(i).dst)||!strcmp(this->H->IPv6, this->iv.ips->at(i).dst_6))))
      this->ipQuery(this->iv.ips->at(i).src, 1);
    std::printf("%s", this->iv.ips->at(i).dns_name_s);
    std::printf("%s", this->iv.ips->at(i).wai_srch_s);
    std::printf("%s", this->iv.ips->at(i).dns_name_d);
    std::printf("%s", this->iv.ips->at(i).wai_srch_d);

    //this->verboInfo(&i);
    //std::printf("%d %s =(%d %s)> %d %s\n", this->iv.ips->at(i).src, this->iv.ips->at(i).src, this->iv.ips->at(i).proto, this->iv.ips->at(i).proto, this->iv.ips->at(i).dst, this->iv.ips->at(i).dst);
  }
}

void getData::ipQuery(char *ip, bool d){
  if(strlen(ip) > 0){

  char *w = (char *)malloc(78), *a = (char *)malloc(48);

  sprintf(a, (char *)"/bin/python3 pyscript.py %s\0", ip);
  system(a);

  FILE *R = fopen("DNS_RESOLUTION", "r");
  if(d){
    fscanf(R, "%s", this->iv.ips->at(this->iv.ipx).dns_name_d);
  }else{
    fscanf(R, "%s", this->iv.ips->at(this->iv.ipx).dns_name_s);
  }
  fclose(R);

  sprintf(w, (char *)"(whois %s | grep OrgName | cut -d' ' -f9-) > WAI\0", ip);
  system(w);

  FILE *W = fopen("WAI", "r");
  if(d){
    fscanf(W, "%s", this->dr.wai_srch_d);
  }else{
    fscanf(W, "%s", this->dr.wai_srch_s);
  }
  fclose(W);

  std::printf("QUERY %s\n", ip);
  }
}

void getData::verboInfo(char *idx){
  std::printf("Direction:\t\t%d\n", this->iv.ips->at(*idx).direcc);
  std::printf("Type:\t\t\tIPv%d\n", (this->iv.ips->at(*idx).ip_v?6:4));
  std::printf("Protocol:\t\t%s\n", this->iv.ips->at(*idx).proto);
  std::printf("Source\n");
  std::printf("\tIP:\t\t%s\n", (this->iv.ips->at(*idx).ip_v? this->iv.ips->at(*idx).src_6 : this->iv.ips->at(*idx).src));
  std::printf("\tPort:\t\t%s\n", (this->iv.ips->at(*idx).tu ? this->iv.ips->at(*idx).u_s_port : this->iv.ips->at(*idx).s_port));
  std::printf("\tMAC:\t\t%s\n", this->iv.ips->at(*idx).s_eth);
  std::printf("\tResolved:\t%s\n", this->iv.ips->at(*idx).s_eth_res);
  std::printf("\tResolved(HW):\t%s\n", this->iv.ips->at(*idx).s_eth_res_oui);
  std::printf("\tDNS Resolved:\t%s\n", this->iv.ips->at(*idx).dns_name_d);
  std::printf("\tWhoIs Resolved:%s\n", this->iv.ips->at(*idx).wai_srch_s);

  std::printf("Destination\n");
  std::printf("\tIP:\t\t%s\n", (this->iv.ips->at(*idx).ip_v? this->iv.ips->at(*idx).dst_6 : this->iv.ips->at(*idx).dst));
  std::printf("\tPort:\t\t%s\n", (this->iv.ips->at(*idx).ia[0]?(this->iv.ips->at(*idx).ia[1]?this->iv.ips->at(*idx).a_src:this->iv.ips->at(*idx).src):(this->iv.ips->at(*idx).tu? this->iv.ips->at(*idx).u_d_port : this->iv.ips->at(*idx).d_port)));
  std::printf("\tMAC:\t\t%s\n", this->iv.ips->at(*idx).d_eth);
  std::printf("\tResolved:\t%s\n", this->iv.ips->at(*idx).d_eth_res);
  std::printf("\tResolved(HW):\t%s\n", this->iv.ips->at(*idx).d_eth_res_oui);
  std::printf("\tDNS Resolved:\t%s\n", this->iv.ips->at(*idx).dns_name_d);
  std::printf("\tWhoIs Resolved:\t%s\n", this->iv.ips->at(*idx).wai_srch_d);
}
