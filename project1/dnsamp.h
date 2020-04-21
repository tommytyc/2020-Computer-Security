#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <arpa/inet.h>
#define PACKET_LENGTH 8192
#define FLAG_Q 0x0120
#define QUERY_ID 0x668e

typedef struct udphdr uh;
typedef struct iphdr  ih;

typedef struct {
	unsigned short query_id;
	unsigned short flags;
	unsigned short qcount;
	unsigned short anscount;
	unsigned short authrr;
	unsigned short addrr;
}dh;

typedef struct {
	unsigned short dnsq_type;
	unsigned short dnsq_class;
}query;

typedef struct {
	unsigned char name;
	unsigned short type;
	unsigned short pld_size;
	unsigned char HinERcode;
	unsigned char EDNS0;
	unsigned short Z;
	unsigned short length;	
}add_rcrd;

typedef struct {
	unsigned int saddr;
	unsigned int daddr;
	unsigned char fill;
	unsigned char proto;
	unsigned short len;
}ph;