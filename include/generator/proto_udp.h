//
// Created by rnborges on 28/04/25.
//

#ifndef PROTO_UDP_H
#define PROTO_UDP_H

#include "ip.h"
#include "packet.h"

/* Estrutura de cabeçalho UDP */
struct udp_header {
    uint16_t source_port;       // Source port
    uint16_t dest_port;         // Destination port
    uint16_t length;            // UDP length (header + data)
    uint16_t checksum;          // Checksum
} __attribute__((packed));

packet_t* create_udp_packet(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    const void *payload, size_t payload_size
);

#endif //PROTO_UDP_H
