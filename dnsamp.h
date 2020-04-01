#pragma once
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <arpa/inet.h>

typedef struct udphdr uh;
typedef struct iphdr  ih;
typedef unsigned short int usint;

typedef struct {
	usint query_id;
	usint flags;
	usint qcnt;
	usint anscnt;
	usint authrr;
	usint addrr;
}dh;

typedef struct {
	usint dnsq_type;
	usint dnsq_class;
}query;