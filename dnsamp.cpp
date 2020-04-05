#include "dnsamp.h"

void PrintError(string error){
    cerr<<error<<endl;
}

void SendDnsPacket(){

}

void SendUdpPacket(){

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

// Calculate IP and UDP checksum
unsigned short CheckSum(int bytes, unsigned short *ptr){
    
}