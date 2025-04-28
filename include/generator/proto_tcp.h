//
// Created by rnborges on 28/04/25.
//

#ifndef PROTO_H
#define PROTO_H

#include "ip.h"
#include "packet.h"

/* Flags TCP */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

/* Estrutura de cabeçalho TCP */
struct tcp_header {
    uint16_t source_port;       // Source port
    uint16_t dest_port;         // Destination port
    uint32_t seq_num;           // Sequence number
    uint32_t ack_num;           // Acknowledgment number
    uint16_t data_offset_flags; // 4 bits data offset, 3 bits reserved, 9 bits flags
    uint16_t window_size;       // Window size
    uint16_t checksum;          // Checksum
    uint16_t urgent_pointer;    // Urgent pointer
} __attribute__((packed));


/* Criação de pacotes */
packet_t* create_tcp_packet(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num, uint8_t flags,
    const void *payload, size_t payload_size
);




#endif //PROTO_H
