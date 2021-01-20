#include "rtr.h"

int main(int argc, char **argv){

  //Initialize var
  getData *g = new getData((char *)"TEST.txt");

  //g->printData();
  g->collection();

  g->printInfo();

  return 0;
}
