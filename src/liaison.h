#ifndef LIAISON_H
#define LIAISON_H
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include "capture.h"



int ethernet(const u_char *,int*,int);
#endif

