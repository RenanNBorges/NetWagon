//
// Created by rnborges on 28/04/25.
//

#ifndef PACKET_H
#define PACKET_H

#include "ip.h"

/* Definição de pacote genérico */
typedef struct packet {
    void *data;               // Ponteiro para dados do pacote
    size_t length;            // Tamanho total do pacote
    ip_version_t ip_version;  // IPv4 ou IPv6
    protocol_type_t protocol; // TCP, UDP, ICMP, etc.
    struct packet *next;      // Próximo pacote na lista
} packet_t;

/* Lista de pacotes */
typedef struct {
    packet_t *head;
    packet_t *tail;
    int count;
} packet_list_t;

uint16_t calculate_checksum(uint16_t *data, size_t length);

/* Inicialização e limpeza da lista */
packet_list_t* create_packet_list();
void free_packet_list(packet_list_t *list);

/* Adicionar pacote à lista */
void add_packet_to_list(packet_list_t *list, packet_t *packet);

void add_ethernet_header(packet_t *packet);

#endif //PACKET_H
