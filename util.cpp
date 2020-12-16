
#include "header.h"
#include "util.h"
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdio>


//formulate the tcp packet, calculae the checksum
void createHeader(TCPIPHeader &header,uint32_t srcIP,uint32_t dstIP,uint16_t dstPort,uint32_t ttl)
{
    memset(&header,'\0',sizeof(TCPIPHeader));

    TCPIPHeader tmpHeader;
    memset(&tmpHeader,'\0',sizeof(TCPIPHeader));

    tmpHeader.ipHeader.tot_len = htons(sizeof(TCPHeader) + strlen(LOADSTRING));
    tmpHeader.ipHeader.dstaddr = dstIP;
    tmpHeader.ipHeader.srcaddr = srcIP;
    tmpHeader.ipHeader.protocol = IPPROTO_TCP;

    tmpHeader.tcpHeader.dst_port = htons(dstPort);
    tmpHeader.tcpHeader.src_port = htons(SRCPORT);
    tmpHeader.tcpHeader.psh = 1;
    tmpHeader.tcpHeader.syn = 1;
    tmpHeader.tcpHeader.seq_no = (rand() << 15) + rand();
    tmpHeader.tcpHeader.ack_no = 0;
    tmpHeader.tcpHeader.thl = sizeof(TCPHeader) / 4;
    tmpHeader.tcpHeader.wnd_size = 0x2000;

    auto len = sizeof(TCPIPHeader) + 12;
    uint8_t* datagram = new uint8_t[len];

    memset(datagram,'\0',len);
    memcpy(datagram,(void*)&tmpHeader,sizeof(TCPIPHeader));
    memcpy(datagram + sizeof(TCPIPHeader),LOADSTRING,strlen(LOADSTRING));

    tmpHeader.tcpHeader.chk_sum = in_cksum((uint16_t*)datagram, len);

    memset(&header,'\0',sizeof(TCPIPHeader));
    header.tcpHeader = tmpHeader.tcpHeader;

    header.ipHeader.ihl = sizeof(IPHeader) / 4;
    header.ipHeader.dstaddr = dstIP;
    header.ipHeader.srcaddr = srcIP;
    header.ipHeader.protocol = IPPROTO_TCP;
    header.ipHeader.version = 4;
    header.ipHeader.id = 0;
    header.ipHeader.ttl = ttl;
    header.ipHeader.tot_len = htons(sizeof(TCPIPHeader) + strlen(LOADSTRING));

    header.ipHeader.chk_sum = in_cksum((uint16_t*)&header, sizeof(IPHeader));

    delete [] datagram;
}

uint16_t in_cksum(uint16_t *addr, int len)
{
    int nleft = len;
    uint16_t *w = addr;
    uint16_t answer;
    int sum = 0;

    /*
    *  Our algorithm is simple, using a 32 bit accumulator (sum),
    *  we add sequential 16 bit words to it, and at the end, fold
    *  back all the carry bits from the top 16 bits into the lower
    *  16 bits.
    */
    while( nleft > 1 )  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if( nleft == 1 ) {
        uint16_t u = 0;

        *(uint8_t *)(&u) = *(uint8_t *)w ;
        sum += u;
    }

    /*
    * add back carry outs from top 16 bits to low 16 bits
    */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    //return (ntohs(answer));
    return (answer);
}

