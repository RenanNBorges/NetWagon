#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stdint.h>
#include <stdlib.h>

#include "packet.h"

// Estrutura para payload com ID único
typedef struct {
    uint32_t id;         // ID único e incremental
    uint32_t timestamp;  // Timestamp para rastreamento
    size_t   data_size;  // Tamanho dos dados
    uint8_t  *data;      // Conteúdo do payload
} unique_payload_t;

// Contador global para IDs
extern uint32_t g_next_payload_id;

// Funções para criação e manipulação de payloads
unique_payload_t* create_unique_payload(const void *data, size_t data_size);
void free_unique_payload(unique_payload_t *payload);
size_t serialize_payload(const unique_payload_t *payload, uint8_t **output);
unique_payload_t* deserialize_payload(const uint8_t *data, size_t length);

packet_t* create_tcp_packet_with_unique_payload(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num, uint8_t flags,
    const unique_payload_t *unique_payload
) ;
packet_t* create_udp_packet_with_unique_payload(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    const unique_payload_t *unique_payload
);

packet_t* create_icmp_packet_with_unique_payload(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint8_t type, uint8_t code, uint16_t id, uint16_t seq,
    const unique_payload_t *unique_payload
);



// Função auxiliar para obter o próximo ID
uint32_t get_next_payload_id();

#endif // PAYLOAD_H