//
// Created by rnborges on 28/04/25.
//

#include "../../include/generator/proto_icmp.h"
#include <stdlib.h>
#include <string.h>

/* Criar pacote ICMP */
packet_t* create_icmp_packet(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint8_t type, uint8_t code, uint16_t id, uint16_t seq,
    const void *payload, size_t payload_size
) {
    packet_t *packet = (packet_t*) malloc(sizeof(packet_t));
    if (!packet) return NULL;

    packet->ip_version = ip_ver;
    packet->protocol = (ip_ver == IP_V4) ? PROTO_ICMP : PROTO_ICMPv6;
    packet->next = NULL;

    size_t ip_header_size = (ip_ver == IP_V4) ? sizeof(struct ip_header_v4) : sizeof(struct ip_header_v6);
    size_t icmp_header_size = sizeof(struct icmp_header);
    packet->length = ip_header_size + icmp_header_size + payload_size;

    packet->data = malloc(packet->length);
    if (!packet->data) {
        free(packet);
        return NULL;
    }

    memset(packet->data, 0, packet->length);

    if (ip_ver == IP_V4) {
        struct ip_header_v4 *ip_header = (struct ip_header_v4*) packet->data;
        struct icmp_header *icmp_header = (struct icmp_header*) (packet->data + ip_header_size);

        /* Preencher cabeçalho IP */
        ip_header->version_ihl = (4 << 4) | 5; // IPv4, IHL=5 (20 bytes)
        ip_header->tos = 0;
        ip_header->total_length = htons(packet->length);
        ip_header->identification = htons(rand() & 0xFFFF);
        ip_header->flags_fragment = htons(0x4000); // Don't fragment
        ip_header->ttl = 64;
        ip_header->protocol = IP_PROTO_ICMP;
        ip_header->source_addr = inet_addr(src_ip);
        ip_header->dest_addr = inet_addr(dst_ip);
        ip_header->header_checksum = 0;

        /* Preencher cabeçalho ICMP */
        icmp_header->type = type;
        icmp_header->code = code;
        icmp_header->checksum = 0;
        icmp_header->un.echo.identifier = htons(id);
        icmp_header->un.echo.sequence = htons(seq);

        /* Copiar payload */
        if (payload && payload_size > 0) {
            memcpy(packet->data + ip_header_size + icmp_header_size, payload, payload_size);
        }

        /* Calcular ICMP checksum */
        size_t icmp_total_size = icmp_header_size + payload_size;
        uint8_t *icmp_buff = (uint8_t*) (packet->data + ip_header_size);
        icmp_header->checksum = calculate_checksum((uint16_t*)icmp_buff, icmp_total_size);

        /* Calcular IP checksum */
        ip_header->header_checksum = calculate_checksum((uint16_t*)ip_header, 20);
    }
    else { // IPv6
        struct ip_header_v6 *ip_header = (struct ip_header_v6*) packet->data;
        struct icmp_header *icmp_header = (struct icmp_header*) (packet->data + ip_header_size);

        /* Preencher cabeçalho IPv6 */
        ip_header->version_class_flow = htonl(6 << 28); // Versão 6
        ip_header->payload_length = htons(icmp_header_size + payload_size);
        ip_header->next_header = IP_PROTO_ICMPV6;
        ip_header->hop_limit = 64;

        /* Converter endereços string para binário */
        inet_pton(AF_INET6, src_ip, ip_header->source_addr);
        inet_pton(AF_INET6, dst_ip, ip_header->dest_addr);

        /* Preencher cabeçalho ICMPv6 */
        icmp_header->type = type;
        icmp_header->code = code;
        icmp_header->checksum = 0;
        icmp_header->un.echo.identifier = htons(id);
        icmp_header->un.echo.sequence = htons(seq);

        /* Copiar payload */
        if (payload && payload_size > 0) {
            memcpy(packet->data + ip_header_size + icmp_header_size, payload, payload_size);
        }

        /* Calcular ICMPv6 checksum (inclui pseudocabeçalho) */
        struct pseudo_header_v6 pseudo;
        memcpy(pseudo.source_addr, ip_header->source_addr, 16);
        memcpy(pseudo.dest_addr, ip_header->dest_addr, 16);
        pseudo.length = htonl(icmp_header_size + payload_size);
        memset(pseudo.zeros, 0, 3);
        pseudo.next_header = IP_PROTO_ICMPV6;

        /* Temporário para cálculo do checksum */
        size_t icmp_total_size = sizeof(struct pseudo_header_v6) + icmp_header_size + payload_size;
        uint8_t *icmp_checksum_buff = (uint8_t*) malloc(icmp_total_size);
        memcpy(icmp_checksum_buff, &pseudo, sizeof(struct pseudo_header_v6));
        memcpy(icmp_checksum_buff + sizeof(struct pseudo_header_v6), icmp_header, icmp_header_size);
        if (payload && payload_size > 0) {
            memcpy(icmp_checksum_buff + sizeof(struct pseudo_header_v6) + icmp_header_size, payload, payload_size);
        }

        icmp_header->checksum = calculate_checksum((uint16_t*)icmp_checksum_buff, icmp_total_size);
        free(icmp_checksum_buff);
    }

    return packet;
}
