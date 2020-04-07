#pragma once
#include <iostream>
#include <string>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <arpa/inet.h>
#define PACKET_LENGTH 8192
#define FLAG_Q 0x0100
#define QUERY_ID 0x668e
using namespace std;

typedef struct udphdr uh;
typedef struct iphdr  ih;
typedef unsigned short int usint;

typedef struct {
	usint query_id;
	usint flags;
	usint qcount;
	usint anscount;
	usint authrr;
	usint addrr;
}dh;

typedef struct {
	usint dnsq_type;
	usint dnsq_class;
}query;