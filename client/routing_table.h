#include <sys/types.h>
#include <netinet/in.h>

#ifndef ROUTING_TABLE_H
#define ROUTING_TABLE_H

#ifdef __cplusplus
extern "C" {
#endif

uint32_t getLocalIPAddress(in_addr_t dst_address);


#ifdef __cplusplus
}
#endif

#endif
