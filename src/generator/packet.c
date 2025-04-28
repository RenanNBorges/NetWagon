//
// Created by rnborges on 28/04/25.
//

#include "../../include/generator/packet.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_SIZE 14
static const uint8_t DEFAULT_DST_MAC[6] = { 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF };
static const uint8_t DEFAULT_SRC_MAC[6] = { 0x11,0x22,0x33,0x44,0x55,0x66 };

/**
 * Prepend a fixed Ethernet header to packet->data.
 */
void add_ethernet_header(packet_t *packet) {
    if (!packet || !packet->data) return;

    size_t oldlen = packet->length;
    uint8_t *old   = packet->data;
    uint8_t *new   = malloc(oldlen + ETHERNET_HEADER_SIZE);
    if (!new) return;

    // Ethernet: DST(6) | SRC(6) | EtherType(2)
    memcpy(new + 0,  DEFAULT_DST_MAC, 6);
    memcpy(new + 6,  DEFAULT_SRC_MAC, 6);
    uint16_t ethertype = htons(
        packet->ip_version == IP_V4 ? 0x0800  // IPv4
                                    : 0x86DD  // IPv6
    );
    memcpy(new + 12, &ethertype, 2);

    // Copia o payload IP/L4 original
    memcpy(new + ETHERNET_HEADER_SIZE, old, oldlen);

    // Substitui buffer
    free(old);
    packet->data   = new;
    packet->length = oldlen + ETHERNET_HEADER_SIZE;
}


/* Função para calcular checksum */
uint16_t calculate_checksum(uint16_t *data, size_t length) {
    uint32_t sum = 0;

    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    if (length == 1) {
        sum += *((uint8_t*) data);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t) ~sum;
}

/* Criar lista de pacotes */
packet_list_t* create_packet_list() {
    packet_list_t *list = (packet_list_t*) malloc(sizeof(packet_list_t));
    if (list) {
        list->head = NULL;
        list->tail = NULL;
        list->count = 0;
    }
    return list;
}

/* Liberar lista de pacotes */
void free_packet_list(packet_list_t *list) {
    if (!list) return;

    packet_t *current = list->head;
    while (current) {
        packet_t *next = current->next;
        if (current->data) {
            free(current->data);
        }
        free(current);
        current = next;
    }

    free(list);
}

/* Adicionar pacote à lista */
void add_packet_to_list(packet_list_t *list, packet_t *packet) {
    if (!list || !packet) return;

    add_ethernet_header(packet);
    packet->next = NULL;

    if (!list->head) {
        list->head = packet;
        list->tail = packet;
    } else {
        list->tail->next = packet;
        list->tail = packet;
    }

    list->count++;
}
