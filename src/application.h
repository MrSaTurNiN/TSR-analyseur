#ifndef APPLICATION_H
#define APPLICATION_H
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <ctype.h>
#include "bootp.h"
#include "capture.h"
#define NOT_PRINTABLE 500//valeur arbitraire supérieur à max(unsigned char) -> cf print_char(char)
#define PORT_FTP_CONTROL_SERVER 21 //pour FTP
//define pour le protocole telnet
//char de controle de session
#define DO 253
#define DONT 254
#define WILL 251
#define WONT 252
#define EC 247//erase char
#define EL 248//erase line
#define GA 249//go ahead
#define SB 250//sub option
#define AO 245//abort output
#define NOP 241//no operation
#define DM 242//data mark
#define IP 244//interupt process
#define AYT 246//are you there
#define IAC 255//Interpret as a command
//option telnet
#define ECHO 1
#define SUPPR_GO_AHEAD 3
#define TERMINAL_TYPE 24
#define WINDOW_SIZE 31
#define TERM_SPEED 32
#define LINE_MODE 34
#define ENV_VAR 36
#define NEW_ENV_VAR 39
//fin d'une suboption
#define SUB_OPTION_END_BYTE_ONE 255 //FF
#define SUB_OPTION_END_BYTE_TWO 240 //F0
//magic cookie pour DHCP
#define MAGIC_COOKIE_BIT_1 0x63
#define MAGIC_COOKIE_BIT_2 0x82
#define MAGIC_COOKIE_BIT_3 0x53
#define MAGIC_COOKIE_BIT_4 0x63

//ne trouvant pas un header dans les .h de mon ordinateur
//j'ai copié une struct trouvé sur internet
struct dns_header{
	unsigned short id; // identification number
  	unsigned char rd :1; // recursion desired
  	unsigned char tc :1; // truncated message
  	unsigned char aa :1; // authoritive answer
  	unsigned char opcode :4; // purpose of message
  	unsigned char qr :1; // query/response flag
  	unsigned char rcode :4; // response code
  	unsigned char cd :1; // checking disabled
  	unsigned char ad :1; // authenticated data
  	unsigned char z :1; // its z! reserved
  	unsigned char ra :1; // recursion available
  	unsigned short q_count; // number of question entries
  	unsigned short ans_count; // number of answer entries
  	unsigned short auth_count; // number of authority entries
  	unsigned short add_count; // number of resource entries
};

/**
 * ensemble des fonctions pour analyser les informations de la couche application
 */
//Application UDP
void dhcp_bootp(const u_char*,int);

void dhcp_translate_operation(int);

void dhcp_vendor(unsigned char*,int);

void dhcp_translate_option(int);

void dns(const u_char*,int,int);

int dns_write_answer(const unsigned char*,int);

//Application TCP
void pop(const u_char*,int,int);

void imap(const u_char*,int,int);

void smtp(const u_char*,int,int);

void http(const u_char*,int,int);

void https(const u_char*,int,int);

void telnet(const u_char*,int,int);

int telnet_option(const unsigned char*);

void telnet_negociation(const u_char*,int);

void ftp_data(const u_char*,int,int);

void ftp_control(const u_char*,int,int,int);

//ecrire le caractère sur la sortie d'erreurs standard si il est imprimable ou . sinon
int print_char(char);

//formalisation de la sortie
void header_application(char*,int);


#endif