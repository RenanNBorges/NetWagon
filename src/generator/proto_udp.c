//
// Created by rnborges on 28/04/25.
//

#include "../../include/generator/proto_udp.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// Helper macro: pad for odd-length checksum buffers
#define UDP_PAD_BYTES(len) (((len) % 2) ? 1 : 0)

packet_t* create_udp_packet(
    ip_version_t ip_ver,
    const char *src_ip,
    const char *dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    const void *payload,
    size_t payload_size
) {
    // Allocate packet structure
    packet_t *packet = calloc(1, sizeof(packet_t));
    if (!packet) return NULL;

    packet->ip_version = ip_ver;
    packet->protocol   = PROTO_UDP;
    packet->next       = NULL;

    // Compute header sizes and total length
    size_t ip_header_size  = (ip_ver == IP_V4)
                             ? sizeof(struct ip_header_v4)
                             : sizeof(struct ip_header_v6);
    size_t udp_header_size = sizeof(struct udp_header);
    packet->length = ip_header_size + udp_header_size + payload_size;

    // Allocate and zero packet data
    packet->data = calloc(1, packet->length);
    if (!packet->data) {
        free(packet);
        return NULL;
    }

    if (ip_ver == IP_V4) {
        struct ip_header_v4 *ip_header = (struct ip_header_v4 *)packet->data;
        struct udp_header  *udp_header = (struct udp_header *)(packet->data + ip_header_size);

        // --- IPv4 header ---
        ip_header->version_ihl     = (4 << 4) | 5;         // IPv4, IHL=5
        ip_header->tos             = 0;
        ip_header->total_length    = htons(packet->length);
        ip_header->identification  = htons(rand() & 0xFFFF);
        ip_header->flags_fragment  = htons(0x4000);        // Don't fragment
        ip_header->ttl             = 64;
        ip_header->protocol        = IP_PROTO_UDP;

        struct in_addr src, dst;
        inet_pton(AF_INET, src_ip, &src);
        inet_pton(AF_INET, dst_ip, &dst);
        ip_header->source_addr     = src.s_addr;
        ip_header->dest_addr       = dst.s_addr;

        // Zero checksum before calculation
        ip_header->header_checksum = 0;

        // --- UDP header ---
        udp_header->source_port = htons(src_port);
        udp_header->dest_port   = htons(dst_port);
        udp_header->length      = htons(udp_header_size + payload_size);
        udp_header->checksum    = 0;

        // Payload copy
        if (payload_size > 0) {
            memcpy(packet->data + ip_header_size + udp_header_size,
                   payload, payload_size);
        }

        // Build pseudo-header v4
        struct pseudo_header_v4 pseudo;
        memset(&pseudo, 0, sizeof(pseudo));
        pseudo.source_addr = ip_header->source_addr;
        pseudo.dest_addr   = ip_header->dest_addr;
        pseudo.reserved    = 0;
        pseudo.protocol    = IP_PROTO_UDP;
        pseudo.length      = htons(udp_header_size + payload_size);

        // Checksum buffer (with padding)
        size_t ps_size = sizeof(pseudo) + udp_header_size + payload_size;
        size_t buf_len = ps_size + UDP_PAD_BYTES(ps_size);
        uint8_t *buf = calloc(1, buf_len);
        if (!buf) {
            free(packet->data);
            free(packet);
            return NULL;
        }
        memcpy(buf, &pseudo, sizeof(pseudo));
        memcpy(buf + sizeof(pseudo), udp_header, udp_header_size);
        if (payload_size > 0) {
            memcpy(buf + sizeof(pseudo) + udp_header_size,
                   payload, payload_size);
        }

        // UDP checksum
        udp_header->checksum = calculate_checksum((uint16_t*)buf, buf_len);
        free(buf);

        // --- IPv4 header checksum (aligned) ---
        {
            // Copy 20 bytes into aligned uint16_t buffer
            uint16_t hdr_buf[sizeof(struct ip_header_v4) / 2];
            memcpy(hdr_buf, ip_header, sizeof(struct ip_header_v4));
            // Ensure checksum words are zero (word index 5 covers bytes 10-11)
            hdr_buf[5] = 0;
            ip_header->header_checksum = calculate_checksum(hdr_buf,
                                            sizeof(struct ip_header_v4));
        }

    } else {
        // --- IPv6 ---
        struct ip_header_v6 *ip_header = (struct ip_header_v6 *)packet->data;
        struct udp_header  *udp_header = (struct udp_header *)(packet->data + ip_header_size);

        ip_header->version_class_flow = htonl(6 << 28);
        ip_header->payload_length     = htons(udp_header_size + payload_size);
        ip_header->next_header        = IP_PROTO_UDP;
        ip_header->hop_limit          = 64;
        inet_pton(AF_INET6, src_ip, ip_header->source_addr);
        inet_pton(AF_INET6, dst_ip, ip_header->dest_addr);

        // --- UDP header ---
        udp_header->source_port = htons(src_port);
        udp_header->dest_port   = htons(dst_port);
        udp_header->length      = htons(udp_header_size + payload_size);
        udp_header->checksum    = 0;

        if (payload_size > 0) {
            memcpy(packet->data + ip_header_size + udp_header_size,
                   payload, payload_size);
        }

        // Build pseudo-header v6
        struct pseudo_header_v6 pseudo;
        memset(&pseudo, 0, sizeof(pseudo));
        memcpy(pseudo.source_addr, ip_header->source_addr, 16);
        memcpy(pseudo.dest_addr,   ip_header->dest_addr,   16);
        pseudo.length      = htonl(udp_header_size + payload_size);
        pseudo.next_header = IP_PROTO_UDP;

        size_t ps_size = sizeof(pseudo) + udp_header_size + payload_size;
        size_t buf_len = ps_size + UDP_PAD_BYTES(ps_size);
        uint8_t *buf = calloc(1, buf_len);
        if (!buf) {
            free(packet->data);
            free(packet);
            return NULL;
        }
        memcpy(buf, &pseudo, sizeof(pseudo));
        memcpy(buf + sizeof(pseudo), udp_header, udp_header_size);
        if (payload_size > 0) {
            memcpy(buf + sizeof(pseudo) + udp_header_size,
                   payload, payload_size);
        }

        udp_header->checksum = calculate_checksum((uint16_t*)buf, buf_len);
        free(buf);
    }

    return packet;
}