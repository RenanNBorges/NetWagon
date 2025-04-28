//
// Created by rnborges on 28/04/25.
//

#ifndef PROTO_ICMP_H
#define PROTO_ICMP_H

#include "ip.h"
#include "packet.h"

/* Estrutura de cabeçalho ICMP */
struct icmp_header {
    uint8_t  type;              // ICMP type
    uint8_t  code;              // ICMP subtype
    uint16_t checksum;          // Checksum
    union {
        struct {
            uint16_t identifier;
            uint16_t sequence;
        } echo;
        uint32_t unused;
    } un;
} __attribute__((packed));

packet_t* create_icmp_packet(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint8_t type, uint8_t code, uint16_t id, uint16_t seq,
    const void *payload, size_t payload_size
);

#endif //PROTO_ICMP_H
