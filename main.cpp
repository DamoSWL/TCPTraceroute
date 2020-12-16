#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <random>
#include <ctime>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "header.h"
#include "util.h"


///////////////////////////////////
///
/// this is tcp-based traceroute program required by network courese
///
/// @author:Weili Shi
/// @email: damoswl@foxmail.com
/// @version:1.1
///
///////////////////////////////////


using namespace std;

void printElapsedTime(const struct timeval* startTime, struct timeval* endTime,double* elapsedTime)
{
    if((startTime == nullptr) || (endTime == nullptr))
    {
        return;
    }

    gettimeofday(endTime,nullptr);
    *elapsedTime = (endTime->tv_sec - startTime->tv_sec)*1000 + (endTime->tv_usec - startTime->tv_usec)/1000.0;

}


//print the final traceroute info on the screen
void printRouteInfo(uint32_t ttl,const in_addr& addr,const double* elapsedTime)
{
    char timeOne[128] = {0};
    char timeTwo[128] = {0};
    char timeThree[128] = {0};

    if(elapsedTime[0] >0)
    {
        snprintf(timeOne,128,"%.4fms",elapsedTime[0]);
    }

    if(elapsedTime[1] >0)
    {
        snprintf(timeTwo,128,"%.4fms",elapsedTime[1]);
    }

    if(elapsedTime[2] >0)
    {
        snprintf(timeThree,128,"%.4fms",elapsedTime[2]);
    }

    fprintf(stdout,"%d    %s     %s     %s    %s\n",ttl,
                            (addr.s_addr >0)? inet_ntoa(addr):"***********",
                            (elapsedTime[0] >0)? timeOne:"********",
                            (elapsedTime[1] >0)? timeTwo:"********",
                            (elapsedTime[2] >0)? timeThree:"********");
}

int main(int argc, char* argv[])
{
    if(argc != 3)
    {
        fprintf(stderr,"wrong input parameter\n");
        fprintf(stdout,"usage: Traceroute dstIP dstPort");
        exit(-1);
    }

    srand ((uint32_t)time(nullptr));

    //create two raw socket
    auto rawSocket_tcp = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    if(rawSocket_tcp < 0)
    {
        perror("rawSocket fail");
        exit(-1);
    }

    auto rawSocket_icmp = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(rawSocket_icmp < 0)
    {
        perror("rawSocket fail");
        exit(-1);
    }


    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if(setsockopt(rawSocket_icmp,SOL_SOCKET,SO_RCVTIMEO,static_cast<void *>(&timeout.tv_sec),sizeof(struct timeval)) < 0)
    {
        perror("setscokopt");
    }

    if(setsockopt(rawSocket_tcp,SOL_SOCKET,SO_RCVTIMEO,static_cast<void *>(&timeout.tv_sec),sizeof(struct timeval)) < 0)
    {
        perror("setscokopt");
    }


    int on = 1;
    if(setsockopt(rawSocket_tcp, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("IP_HDRINCL failed");
        exit(1);
    }

    uint32_t srcIP = 0;

    struct ifaddrs *addr = nullptr;
    struct ifaddrs *tmpaddr = nullptr;
    getifaddrs(&addr);


    //acquire the lcoal IP address
    tmpaddr = addr;
    while(tmpaddr != nullptr)
    {
        if(tmpaddr->ifa_addr->sa_family == AF_INET)
        {
            if((strncmp(tmpaddr->ifa_name,"lo",2) != 0) && strncmp(tmpaddr->ifa_name,"virbr",5) != 0)
            {
                srcIP = ((struct sockaddr_in*)tmpaddr->ifa_addr)->sin_addr.s_addr;
            }
        }

        tmpaddr = tmpaddr->ifa_next;
    }

    freeifaddrs(addr);

    in_addr displayAddr;
    displayAddr.s_addr = srcIP;
    cout << "your local IP address is " << inet_ntoa(displayAddr) << endl;

    struct hostent *hptr = nullptr;
    hptr = gethostbyname(argv[1]); //obtain the destination IP address
    if(!hptr)
    {
        fprintf(stderr,"fail to get IP address from hostname");
        exit(-1);
    }

    char* dstIPstr = inet_ntoa(*(struct in_addr*)hptr->h_addr_list[0]);
    printf("destination IP address is : %s\n",dstIPstr);
    

    uint32_t dstIP = inet_addr(dstIPstr);
    uint16_t dstPort = strtol(argv[2],nullptr,10);

    struct sockaddr_in dstAddr;
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_addr.s_addr = dstIP;// inet_addr("104.193.88.123");
    dstAddr.sin_port = htons(dstPort);


    for(uint32_t ttl = 1; ttl <= MAX_TTL; ttl++)  //in the loop send the raw socket and analyze the returen socket
    {
        TCPIPHeader header;
        createHeader(header,srcIP,dstIP,dstPort,ttl);

        auto len = sizeof(TCPIPHeader) + strlen(LOADSTRING);
        uint8_t *datagram = new uint8_t[len];
        memset(datagram,'\0',len);
        memcpy(datagram,&header,sizeof(TCPIPHeader));
        memcpy(datagram + sizeof(TCPIPHeader),LOADSTRING,strlen(LOADSTRING));

        double elapsedTime[3] = {-1,-1,-1};
        struct in_addr tmpIPAddr = {0};

        bool breakFlag = false;
        bool icmpRevFlag = false;
        bool tcpRevFlag = false;
        bool indexResetFlag = false;

        for(int i = 0; i < 3; i++)
        {
            struct timeval startTime;
            struct timeval endTime;

            if(tcpRevFlag)  //reset the index
            {
                if(!indexResetFlag)
                {
                    i = 0;
                    indexResetFlag = true;
                }
            }

            gettimeofday(&startTime,nullptr);

            if(sendto(rawSocket_tcp,datagram,len,0,(const struct sockaddr*)&dstAddr,sizeof(struct sockaddr)) < 0)
            {
                perror("sendto");
            }

            uint8_t dataBuf[128] = {'\0'};
            socklen_t sockLen = sizeof(struct sockaddr);
            ssize_t dataLen = 0;

            if(!tcpRevFlag)
            {
                dataLen = recvfrom(rawSocket_icmp,dataBuf,128,0,(struct sockaddr*)&dstAddr,&sockLen);
                if(dataLen >= static_cast<ssize_t>(sizeof(ICMPTCPIPHeader) + strlen(LOADSTRING)))
                {
                    ICMPTCPIPHeader recvHeader;
                    memcpy((void*)&recvHeader,dataBuf,sizeof(ICMPTCPIPHeader));

                    //filter the incoming icmp packets
                    if(recvHeader.ipHeader.protocol == IPPROTO_ICMP)
                    {
                        if((recvHeader.ipHeader.dstaddr == srcIP) &&
                            (recvHeader.tcpHeader_origin.src_port == htons(SRCPORT)))
                        {
                            icmpRevFlag = true;
                            tmpIPAddr.s_addr = recvHeader.ipHeader.srcaddr;

                            switch(recvHeader.icmpHeader.type)
                            {
                            case ICMP::DEST_UNREACH:
                                printElapsedTime(&startTime,&endTime,&elapsedTime[i]);
                                break;

                            case ICMP::REDIRECT:
                                cout << "icmp redirect" << endl;
                                breakFlag = true;
                                break;

                            case ICMP::TTL_EXPIRED:
                                printElapsedTime(&startTime,&endTime,&elapsedTime[i]);
                                break;

                            default:
                                break;

                            }

                            if((recvHeader.icmpHeader.type == ICMP::DEST_UNREACH) &&
                                    (recvHeader.ipHeader.srcaddr == dstIP) && (i == 2))
                            {
                                breakFlag = true;
                            }

                        }
                    }
                }

            }

            if(icmpRevFlag)
            {
                icmpRevFlag = false;
                continue;
            }

            memset(dataBuf,'\0',sizeof(dataBuf));
            if(recvfrom(rawSocket_tcp,dataBuf,128,0,(struct sockaddr*)&dstAddr,&sockLen) > 0)
            {
                TCPIPHeader recvHeader;
                memcpy((void*)&recvHeader,dataBuf,sizeof(TCPIPHeader));

                //filter the incoming tcp packets
                if(recvHeader.ipHeader.protocol == IPPROTO_TCP)
                {
                    if((recvHeader.ipHeader.dstaddr == srcIP) &&
                        (recvHeader.tcpHeader.dst_port == htons(SRCPORT)))
                    {
                        if((recvHeader.tcpHeader.syn && recvHeader.tcpHeader.ack) || recvHeader.tcpHeader.rst)
                        {
                            tcpRevFlag = true;

                            tmpIPAddr.s_addr = recvHeader.ipHeader.srcaddr;
                            printElapsedTime(&startTime,&endTime,&elapsedTime[i]);


                            if(recvHeader.ipHeader.srcaddr == dstIP)
                            {
                                breakFlag = true;
                            }
                        }
                    }
                }
            }

        }

        printRouteInfo(ttl,tmpIPAddr,elapsedTime);

        if(breakFlag)
        {
            delete [] datagram;
            break;
        }

    }

}
