/**
 * packet_builder.h
 * Biblioteca simples para construção de pacotes de rede IPv4/IPv6
 */

#ifndef IP_H
#define IP_H

#include <arpa/inet.h>

/* Tipos de pacotes suportados */
typedef enum {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_ICMPv6
} protocol_type_t;

/* Versão IP */
typedef enum {
    IP_V4,
    IP_V6
} ip_version_t;

/* Estrutura de cabeçalho IPv4 */
struct ip_header_v4 {
    uint8_t  version_ihl;      // 4 bits version, 4 bits header length
    uint8_t  tos;              // Type of service
    uint16_t total_length;     // Total packet length
    uint16_t identification;   // Identification
    uint16_t flags_fragment;   // 3 bits flags, 13 bits fragment offset
    uint8_t  ttl;              // Time to live
    uint8_t  protocol;         // Protocol (TCP, UDP, ICMP)
    uint16_t header_checksum;  // Header checksum
    uint32_t source_addr;      // Source address
    uint32_t dest_addr;        // Destination address
} __attribute__((packed));

/* Estrutura de cabeçalho IPv6 */
struct ip_header_v6 {
    uint32_t version_class_flow; // 4 bits version, 8 bits traffic class, 20 bits flow label
    uint16_t payload_length;     // Payload length
    uint8_t  next_header;        // Next header (equivalent to protocol in IPv4)
    uint8_t  hop_limit;          // Hop limit (equivalent to TTL in IPv4)
    uint8_t  source_addr[16];    // Source address (128 bits)
    uint8_t  dest_addr[16];      // Destination address (128 bits)
} __attribute__((packed));


/* Estruturas auxiliares para cálculo de checksums */
struct pseudo_header_v4 {
    uint32_t source_addr;
    uint32_t dest_addr;
    uint8_t  reserved;
    uint8_t  protocol;
    uint16_t length;
} __attribute__((packed));

struct pseudo_header_v6 {
    uint8_t  source_addr[16];
    uint8_t  dest_addr[16];
    uint32_t length;
    uint8_t  zeros[3];
    uint8_t  next_header;
} __attribute__((packed));

/* Protocolos para cabeçalhos IP */
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17
#define IP_PROTO_ICMP 1
#define IP_PROTO_ICMPV6 58



#endif /* IP_H */