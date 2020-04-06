#include "dnsamp.h"

void PrintError(string error){
    cerr<<error<<endl;
}

void SendDnsPacket(){

}

void CreateDnsHeader(dh *dns){
    dns->query_id = (unsigned short) htons(getpid());
    dns->addrr = 0;
    dns->anscount = 0;
    dns->authrr = 0;
    dns->flags = 0;
    dns->qcount = htons(1);
}

void CreateQueryInfo(query *q){
    q->dnsq_class = htons(1);
    q->dnsq_type = htons(1);
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