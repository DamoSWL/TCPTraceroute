#ifndef HEADER_H
#define HEADER_H

#include <cstdint>

#define LOADSTRING "CSCI6760-f19"
#define SRCPORT 8990
#define MAX_TTL 30

namespace ICMP
{
    enum
    {
        ECHO_REP = 0,
        ECHO_REQ = 8,
        DEST_UNREACH = 3,
        TTL_EXPIRED = 11,
        SOURCE_QUENCH = 4,
        REDIRECT = 5
    };
}


typedef struct _IPHeader
{
    uint8_t ihl : 4;
    uint8_t version : 4;

    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t chk_sum;
    uint32_t srcaddr;
    uint32_t dstaddr;

}IPHeader;


typedef struct _TCPHeadr
{
    uint16_t src_port;    //源端口号
    uint16_t dst_port;    //目的端口号
    uint32_t seq_no;        //序列号
    uint32_t ack_no;        //确认号

    uint8_t reserved_1:4; //保留6位中的4位首部长度
    uint8_t thl:4;        //tcp头部长度

    uint8_t fin : 1;
    uint8_t syn : 1;
    uint8_t rst : 1;
    uint8_t psh : 1;
    uint8_t ack : 1;
    uint8_t urg : 1;
    uint8_t ece : 1;
    uint8_t cwr : 1;


    uint16_t wnd_size;    //16位窗口大小
    uint16_t chk_sum;     //16位TCP检验和
    uint16_t urgt_p;      //16为紧急指针
}TCPHeader;



typedef struct _ICMPHeader
{
    uint8_t type;   //类型
    uint8_t code;        //代码
    uint16_t chk_sum;    //16位检验和
    uint16_t reserved_1;
    uint16_t reserved_2;
}ICMPHeader;


typedef struct _TCPIPHeader
{
    IPHeader ipHeader;
    TCPHeader tcpHeader;
}TCPIPHeader;


typedef struct _ICMPTCPIPHeader
{
    IPHeader ipHeader;
    ICMPHeader icmpHeader;
    IPHeader ipHeader_origin;
    TCPHeader tcpHeader_origin;

}ICMPTCPIPHeader;






#endif // HEADER_H
