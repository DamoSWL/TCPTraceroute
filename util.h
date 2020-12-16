#ifndef UTIL_H
#define UTIL_H

#include "header.h"
#include <cstdint>

uint16_t in_cksum(uint16_t *addr, int len);
void createHeader(TCPIPHeader& header,uint32_t srcIP,uint32_t dstIP,uint16_t dstPort,uint32_t ttl);



#endif // UTIL_H
