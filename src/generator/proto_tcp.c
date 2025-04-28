//
// Created by rnborges on 28/04/25.
//

#include "../../include/generator/proto_tcp.h"
#include <string.h>
#include "stdlib.h"

packet_t* create_tcp_packet(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num, uint8_t flags,
    const void *payload, size_t payload_size
) {
    packet_t *packet = (packet_t*) malloc(sizeof(packet_t));
    if (!packet) return NULL;

    packet->ip_version = ip_ver;
    packet->protocol = PROTO_TCP;
    packet->next = NULL;

    size_t ip_header_size = (ip_ver == IP_V4) ? sizeof(struct ip_header_v4) : sizeof(struct ip_header_v6);
    size_t tcp_header_size = sizeof(struct tcp_header);
    packet->length = ip_header_size + tcp_header_size + payload_size;

    packet->data = malloc(packet->length);
    if (!packet->data) {
        free(packet);
        return NULL;
    }

    memset(packet->data, 0, packet->length);

    if (ip_ver == IP_V4) {
        struct ip_header_v4 *ip_header = (struct ip_header_v4*) packet->data;
        struct tcp_header *tcp_header = (struct tcp_header*) (packet->data + ip_header_size);

        ip_header->version_ihl = (4 << 4) | 5;
        ip_header->tos = 0;
        ip_header->total_length = htons(packet->length);
        ip_header->identification = htons(rand() & 0xFFFF);
        ip_header->flags_fragment = htons(0x4000);
        ip_header->ttl = 64;
        ip_header->protocol = IP_PROTO_TCP;
        ip_header->source_addr = inet_addr(src_ip);
        ip_header->dest_addr = inet_addr(dst_ip);
        ip_header->header_checksum = 0;

        /* Preencher cabeçalho TCP */
        tcp_header->source_port = htons(src_port);
        tcp_header->dest_port = htons(dst_port);
        tcp_header->seq_num = htonl(seq_num);
        tcp_header->ack_num = htonl(ack_num);
        tcp_header->data_offset_flags = htons((5 << 12) | flags); // Data offset = 5, flags
        tcp_header->window_size = htons(5840);
        tcp_header->urgent_pointer = 0;

        /* Copiar payload */
        if (payload && payload_size > 0) {
            memcpy(packet->data + ip_header_size + tcp_header_size, payload, payload_size);
        }

        /* Calcular TCP checksum */
        struct pseudo_header_v4 pseudo;
        pseudo.source_addr = ip_header->source_addr;
        pseudo.dest_addr = ip_header->dest_addr;
        pseudo.reserved = 0;
        pseudo.protocol = IP_PROTO_TCP;
        pseudo.length = htons(tcp_header_size + payload_size);

        /* Temporário para cálculo do checksum */
        size_t tcp_total_size = sizeof(struct pseudo_header_v4) + tcp_header_size + payload_size;
        uint8_t *tcp_checksum_buff = (uint8_t*) malloc(tcp_total_size);
        memcpy(tcp_checksum_buff, &pseudo, sizeof(struct pseudo_header_v4));
        memcpy(tcp_checksum_buff + sizeof(struct pseudo_header_v4), tcp_header, tcp_header_size);
        if (payload && payload_size > 0) {
            memcpy(tcp_checksum_buff + sizeof(struct pseudo_header_v4) + tcp_header_size, payload, payload_size);
        }

        tcp_header->checksum = calculate_checksum((uint16_t*)tcp_checksum_buff, tcp_total_size);
        free(tcp_checksum_buff);

        /* Calcular IP checksum */
        ip_header->header_checksum = calculate_checksum((uint16_t*)ip_header, 20);
    }
    else { // IPv6
        struct ip_header_v6 *ip_header = (struct ip_header_v6*) packet->data;
        struct tcp_header *tcp_header = (struct tcp_header*) (packet->data + ip_header_size);

        /* Preencher cabeçalho IPv6 */
        ip_header->version_class_flow = htonl(6 << 28); // Versão 6
        ip_header->payload_length = htons(tcp_header_size + payload_size);
        ip_header->next_header = IP_PROTO_TCP;
        ip_header->hop_limit = 64;

        /* Converter endereços string para binário */
        inet_pton(AF_INET6, src_ip, ip_header->source_addr);
        inet_pton(AF_INET6, dst_ip, ip_header->dest_addr);

        /* Preencher cabeçalho TCP */
        tcp_header->source_port = htons(src_port);
        tcp_header->dest_port = htons(dst_port);
        tcp_header->seq_num = htonl(seq_num);
        tcp_header->ack_num = htonl(ack_num);
        tcp_header->data_offset_flags = htons((5 << 12) | flags); // Data offset = 5, flags
        tcp_header->window_size = htons(5840);
        tcp_header->urgent_pointer = 0;

        /* Copiar payload */
        if (payload && payload_size > 0) {
            memcpy(packet->data + ip_header_size + tcp_header_size, payload, payload_size);
        }

        /* Calcular TCP checksum */
        struct pseudo_header_v6 pseudo;
        memcpy(pseudo.source_addr, ip_header->source_addr, 16);
        memcpy(pseudo.dest_addr, ip_header->dest_addr, 16);
        pseudo.length = htonl(tcp_header_size + payload_size);
        memset(pseudo.zeros, 0, 3);
        pseudo.next_header = IP_PROTO_TCP;

        size_t tcp_total_size = sizeof(struct pseudo_header_v6) + tcp_header_size + payload_size;
        uint8_t *tcp_checksum_buff = (uint8_t*) malloc(tcp_total_size);
        memcpy(tcp_checksum_buff, &pseudo, sizeof(struct pseudo_header_v6));
        memcpy(tcp_checksum_buff + sizeof(struct pseudo_header_v6), tcp_header, tcp_header_size);
        if (payload && payload_size > 0) {
            memcpy(tcp_checksum_buff + sizeof(struct pseudo_header_v6) + tcp_header_size, payload, payload_size);
        }

        tcp_header->checksum = calculate_checksum((uint16_t*)tcp_checksum_buff, tcp_total_size);
        free(tcp_checksum_buff);
    }

    return packet;
}