#ifndef TRANSPORT_H
#define TRANSPORT_H
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "capture.h"
#define BUFFER_OPTION_TCP 50
int udp(const u_char*,int*,int*, int );

int tcp(const u_char*,int* ,int*,int,int);

void option_tcp(const u_char*,int);

void flag_tcp(struct tcphdr*);

void tcp_translate_option(int);
#endif