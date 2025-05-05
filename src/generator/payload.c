#include "../../include/generator/payload.h"
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "generator/packet.h"
#include "generator/proto_icmp.h"
#include "generator/proto_tcp.h"
#include "generator/proto_udp.h"

// Inicialização do contador global de IDs
uint32_t g_next_payload_id = 1;

// Obtém o próximo ID único
uint32_t get_next_payload_id() {
    return g_next_payload_id++;
}

// Cria um novo payload com ID único
unique_payload_t* create_unique_payload(const void *data, size_t data_size) {
    unique_payload_t *payload = (unique_payload_t*) malloc(sizeof(unique_payload_t));
    if (!payload) return NULL;

    // Atribuir ID único e timestamp
    payload->id = get_next_payload_id();
    payload->timestamp = (uint32_t)time(NULL);
    payload->data_size = data_size;

    // Alocar e copiar dados
    if (data_size > 0 && data != NULL) {
        payload->data = (uint8_t*) malloc(data_size);
        if (!payload->data) {
            free(payload);
            return NULL;
        }
        memcpy(payload->data, data, data_size);
    } else {
        payload->data = NULL;
        payload->data_size = 0;
    }

    return payload;
}

// Libera recursos do payload
void free_unique_payload(unique_payload_t *payload) {
    if (!payload) return;
    
    if (payload->data) {
        free(payload->data);
    }
    free(payload);
}

// Serializa o payload para um buffer contínuo
size_t serialize_payload(const unique_payload_t *payload, uint8_t **output) {
    if (!payload) return 0;

    // Tamanho total: id(4) + timestamp(4) + data_size(4) + data(data_size)
    size_t total_size = 12 + payload->data_size;
    *output = (uint8_t*) malloc(total_size);
    if (!*output) return 0;

    // Conversão para network byte order
    uint32_t net_id = htonl(payload->id);
    uint32_t net_timestamp = htonl(payload->timestamp);
    uint32_t net_data_size = htonl(payload->data_size);

    // Montar o buffer
    memcpy(*output, &net_id, 4);
    memcpy(*output + 4, &net_timestamp, 4);
    memcpy(*output + 8, &net_data_size, 4);
    
    if (payload->data_size > 0 && payload->data != NULL) {
        memcpy(*output + 12, payload->data, payload->data_size);
    }

    return total_size;
}

// Deserializa um buffer para estrutura unique_payload_t
unique_payload_t* deserialize_payload(const uint8_t *data, size_t length) {
    if (!data || length < 12) return NULL;  // Pelo menos cabeçalho

    unique_payload_t *payload = (unique_payload_t*) malloc(sizeof(unique_payload_t));
    if (!payload) return NULL;

    // Extrair valores e converter para host byte order
    uint32_t net_id, net_timestamp, net_data_size;
    memcpy(&net_id, data, 4);
    memcpy(&net_timestamp, data + 4, 4);
    memcpy(&net_data_size, data + 8, 4);

    payload->id = ntohl(net_id);
    payload->timestamp = ntohl(net_timestamp);
    payload->data_size = ntohl(net_data_size);

    // Verificar consistência dos dados
    if (payload->data_size > 0) {
        if (12 + payload->data_size > length) {
            // Dados incompletos
            free(payload);
            return NULL;
        }

        payload->data = (uint8_t*) malloc(payload->data_size);
        if (!payload->data) {
            free(payload);
            return NULL;
        }
        memcpy(payload->data, data + 12, payload->data_size);
    } else {
        payload->data = NULL;
    }

    return payload;
}

// Funções de extensão para criar pacotes com payload único

// Função auxiliar para associar payload à funções de criação de pacote existentes
packet_t* create_packet_with_unique_payload(
    packet_t* (*create_func)(ip_version_t, const char*, const char*, ...),
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    void *extra_params,
    const unique_payload_t *unique_payload
) {
    uint8_t *serialized_data = NULL;
    size_t data_size = serialize_payload(unique_payload, &serialized_data);
    if (!data_size || !serialized_data) return NULL;
    
    packet_t *packet = NULL;
    
    // Este é um exemplo, você terá que adaptar para cada protocolo
    // conforme suas necessidades específicas
    
    // Liberar recursos temporários
    free(serialized_data);
    
    return packet;
}

// Exemplos de funções para cada protocolo com payload único

// TCP com payload único
packet_t* create_tcp_packet_with_unique_payload(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num, uint8_t flags,
    const unique_payload_t *unique_payload
) {
    uint8_t *buffer = NULL;
    size_t size = serialize_payload(unique_payload, &buffer);
    if (!size || !buffer) return NULL;
    
    packet_t *packet = create_tcp_packet(
        ip_ver, src_ip, dst_ip,
        src_port, dst_port,
        seq_num, ack_num, flags,
        buffer, size
    );
    
    free(buffer);
    return packet;
}

// UDP com payload único
packet_t* create_udp_packet_with_unique_payload(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    const unique_payload_t *unique_payload
) {
    uint8_t *buffer = NULL;
    size_t size = serialize_payload(unique_payload, &buffer);
    if (!size || !buffer) return NULL;
    
    packet_t *packet = create_udp_packet(
        ip_ver, src_ip, dst_ip,
        src_port, dst_port,
        buffer, size
    );
    
    free(buffer);
    return packet;
}

// ICMP com payload único
packet_t* create_icmp_packet_with_unique_payload(
    ip_version_t ip_ver,
    const char *src_ip, const char *dst_ip,
    uint8_t type, uint8_t code, uint16_t id, uint16_t seq,
    const unique_payload_t *unique_payload
) {
    uint8_t *buffer = NULL;
    size_t size = serialize_payload(unique_payload, &buffer);
    if (!size || !buffer) return NULL;
    
    packet_t *packet = create_icmp_packet(
        ip_ver, src_ip, dst_ip,
        type, code, id, seq,
        buffer, size
    );
    
    free(buffer);
    return packet;
}