/**
 * rtt_measurement.c - Módulo para medição precisa de RTT (Round Trip Time)
 *
 * Este módulo implementa uma medição precisa do tempo de ida e volta dos pacotes
 * usando timestamps de alta resolução e mecanismos de correlação.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "rtt_measurement.h"

// Tamanho da tabela hash para correlação de pacotes
#define HASH_TABLE_SIZE 65536

// Estrutura interna para armazenar detalhes de um pacote enviado
typedef struct packet_record {
    uint32_t hash;               // Hash do pacote para identificação
    uint64_t send_time;          // Timestamp de envio (microssegundos)
    uint8_t protocol;            // Protocolo (TCP, UDP, ICMP)
    uint8_t responded;           // Flag indicando se recebeu resposta
    uint16_t src_port;           // Porta de origem
    uint16_t dst_port;           // Porta de destino
    uint32_t seq_num;            // Número de sequência (TCP/ICMP)
    struct in_addr src_addr;     // Endereço IP origem
    struct in_addr dst_addr;     // Endereço IP destino
    struct packet_record *next;  // Próximo na lista (para colisões)
} packet_record_t;

// Estrutura de dados interna para o estado do módulo
struct rtt_context {
    packet_record_t *hash_table[HASH_TABLE_SIZE];  // Tabela hash para correlação
    pthread_mutex_t mutex;                         // Mutex para acesso concorrente
    rtt_stats_t stats;                             // Estatísticas agregadas
    uint32_t next_packet_id;                       // ID sequencial para pacotes
    int initialized;                               // Flag de inicialização
};

// Função que calcula um hash simples para um pacote
static uint32_t calculate_packet_hash(const uint8_t *packet_data,
                                       uint32_t protocol,
                                       struct in_addr src_addr,
                                       struct in_addr dst_addr,
                                       uint16_t src_port,
                                       uint16_t dst_port,
                                       uint32_t seq_num) {
    // Um hash simples baseado nos principais campos do pacote
    uint32_t hash = 17;
    hash = hash * 31 + protocol;
    hash = hash * 31 + src_addr.s_addr;
    hash = hash * 31 + dst_addr.s_addr;
    hash = hash * 31 + src_port;
    hash = hash * 31 + dst_port;
    hash = hash * 31 + seq_num;

    return hash % HASH_TABLE_SIZE;
}

// Obter timestamp atual em microssegundos
static uint64_t get_timestamp_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

// Inicializar o contexto de medição RTT
rtt_context_t* rtt_init() {
    rtt_context_t *ctx = (rtt_context_t*)malloc(sizeof(rtt_context_t));
    if (!ctx) {
        return NULL;
    }

    // Inicializar a tabela hash
    memset(ctx->hash_table, 0, sizeof(ctx->hash_table));

    // Inicializar mutex
    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        free(ctx);
        return NULL;
    }

    // Inicializar estatísticas
    memset(&ctx->stats, 0, sizeof(rtt_stats_t));
    ctx->stats.min_rtt = UINT64_MAX;

    ctx->next_packet_id = 1;
    ctx->initialized = 1;

    return ctx;
}

// Liberar recursos do contexto RTT
void rtt_cleanup(rtt_context_t *ctx) {
    if (!ctx || !ctx->initialized) {
        return;
    }

    // Liberar registros na tabela hash
    pthread_mutex_lock(&ctx->mutex);
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        packet_record_t *record = ctx->hash_table[i];
        while (record) {
            packet_record_t *next = record->next;
            free(record);
            record = next;
        }
        ctx->hash_table[i] = NULL;
    }
    pthread_mutex_unlock(&ctx->mutex);

    // Destruir mutex
    pthread_mutex_destroy(&ctx->mutex);

    // Liberar contexto
    ctx->initialized = 0;
    free(ctx);
}

// Registrar um pacote enviado para medição de RTT
packet_id_t rtt_register_packet_sent(rtt_context_t *ctx,
                                   const packet_t *packet,
                                   uint8_t protocol,
                                   struct in_addr src_addr,
                                   struct in_addr dst_addr,
                                   uint16_t src_port,
                                   uint16_t dst_port,
                                   uint32_t seq_num) {
    if (!ctx || !ctx->initialized || !packet) {
        return 0;
    }

    uint64_t now = get_timestamp_us();

    // Calcular hash do pacote
    uint32_t hash = calculate_packet_hash(packet->data,
                                          protocol,
                                          src_addr, dst_addr,
                                          src_port, dst_port,
                                          seq_num);

    // Criar um novo registro
    packet_record_t *record = (packet_record_t*)malloc(sizeof(packet_record_t));
    if (!record) {
        return 0;
    }

    record->hash = hash;
    record->send_time = now;
    record->protocol = protocol;
    record->responded = 0;
    record->src_port = src_port;
    record->dst_port = dst_port;
    record->seq_num = seq_num;
    record->src_addr = src_addr;
    record->dst_addr = dst_addr;
    record->next = NULL;

    // Adicionar à tabela hash
    pthread_mutex_lock(&ctx->mutex);

    // Atualizar estatísticas
    ctx->stats.packets_sent++;

    // Inserir no início da lista para este bucket
    record->next = ctx->hash_table[hash];
    ctx->hash_table[hash] = record;

    // Gerar e retornar ID único para este pacote
    packet_id_t packet_id = ctx->next_packet_id++;

    pthread_mutex_unlock(&ctx->mutex);

    return packet_id;
}

// Processar um pacote recebido e calcular RTT
rtt_sample_t rtt_process_packet_received(rtt_context_t *ctx,
                                      const uint8_t *packet_data,
                                      uint32_t packet_len,
                                      uint8_t protocol,
                                      struct in_addr src_addr,
                                      struct in_addr dst_addr,
                                      uint16_t src_port,
                                      uint16_t dst_port,
                                      uint32_t seq_num) {
    rtt_sample_t result;
    memset(&result, 0, sizeof(rtt_sample_t));
    result.rtt = 0;
    result.valid = 0;

    if (!ctx || !ctx->initialized || !packet_data) {
        return result;
    }

    uint64_t receive_time = get_timestamp_us();

    // Para correlacionar, invertemos src/dst em relação ao pacote enviado
    uint32_t hash = calculate_packet_hash(packet_data,
                                          protocol,
                                          dst_addr, src_addr,  // Invertido
                                          dst_port, src_port,  // Invertido
                                          seq_num);

    pthread_mutex_lock(&ctx->mutex);

    // Procurar pacote correspondente
    packet_record_t *prev = NULL;
    packet_record_t *record = ctx->hash_table[hash];

    while (record) {
        // Verificar se é o pacote que estamos procurando
        // Em uma implementação mais robusta, você checaria mais campos
        if (record->hash == hash &&
            record->protocol == protocol &&
            record->src_addr.s_addr == dst_addr.s_addr &&
            record->dst_addr.s_addr == src_addr.s_addr &&
            record->src_port == dst_port &&
            record->dst_port == src_port) {

            // Calcular RTT
            uint64_t rtt = receive_time - record->send_time;

            // Preencher dados da amostra
            result.valid = 1;
            result.rtt = rtt;
            result.protocol = protocol;
            result.src_addr = record->src_addr;
            result.dst_addr = record->dst_addr;
            result.src_port = record->src_port;
            result.dst_port = record->dst_port;
            result.seq_num = record->seq_num;
            result.send_time = record->send_time;
            result.receive_time = receive_time;

            // Atualizar estatísticas
            ctx->stats.packets_received++;
            ctx->stats.total_rtt += rtt;

            if (rtt < ctx->stats.min_rtt) {
                ctx->stats.min_rtt = rtt;
            }
            if (rtt > ctx->stats.max_rtt) {
                ctx->stats.max_rtt = rtt;
            }

            // Cálculo do jitter (variação de RTT)
            if (ctx->stats.packets_received > 1) {
                uint64_t jitter;
                if (rtt > ctx->stats.last_rtt) {
                    jitter = rtt - ctx->stats.last_rtt;
                } else {
                    jitter = ctx->stats.last_rtt - rtt;
                }

                ctx->stats.total_jitter += jitter;
                if (jitter > ctx->stats.max_jitter) {
                    ctx->stats.max_jitter = jitter;
                }

                result.jitter = jitter;
            } else {
                result.jitter = 0;
            }

            ctx->stats.last_rtt = rtt;

            // Remover o registro da tabela (já encontramos a resposta)
            if (prev) {
                prev->next = record->next;
            } else {
                ctx->hash_table[hash] = record->next;
            }

            free(record);
            break;
        }

        prev = record;
        record = record->next;
    }

    pthread_mutex_unlock(&ctx->mutex);

    return result;
}

// Obter estatísticas atuais
rtt_stats_t rtt_get_stats(rtt_context_t *ctx) {
    rtt_stats_t stats;
    memset(&stats, 0, sizeof(rtt_stats_t));

    if (!ctx || !ctx->initialized) {
        return stats;
    }

    pthread_mutex_lock(&ctx->mutex);
    memcpy(&stats, &ctx->stats, sizeof(rtt_stats_t));
    pthread_mutex_unlock(&ctx->mutex);

    return stats;
}

// Limpar pacotes antigos que não receberam resposta
void rtt_cleanup_old_packets(rtt_context_t *ctx, uint64_t timeout_us) {
    if (!ctx || !ctx->initialized) {
        return;
    }

    uint64_t now = get_timestamp_us();
    uint64_t cutoff_time = now - timeout_us;

    pthread_mutex_lock(&ctx->mutex);

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        packet_record_t *prev = NULL;
        packet_record_t *record = ctx->hash_table[i];

        while (record) {
            if (record->send_time < cutoff_time) {
                // Este pacote excedeu o timeout, remover
                packet_record_t *to_remove = record;

                if (prev) {
                    prev->next = record->next;
                    record = record->next;
                } else {
                    ctx->hash_table[i] = record->next;
                    record = ctx->hash_table[i];
                }

                // Atualizar estatística de perda de pacotes
                ctx->stats.packets_lost++;

                free(to_remove);
            } else {
                prev = record;
                record = record->next;
            }
        }
    }

    pthread_mutex_unlock(&ctx->mutex);
}

// Reset das estatísticas
void rtt_reset_stats(rtt_context_t *ctx) {
    if (!ctx || !ctx->initialized) {
        return;
    }

    pthread_mutex_lock(&ctx->mutex);

    memset(&ctx->stats, 0, sizeof(rtt_stats_t));
    ctx->stats.min_rtt = UINT64_MAX;

    pthread_mutex_unlock(&ctx->mutex);
}

// Extrair protocolo, endereços e portas de um pacote recebido
int rtt_extract_packet_info(const uint8_t *packet_data,
                          uint32_t packet_len,
                          uint8_t *protocol,
                          struct in_addr *src_addr,
                          struct in_addr *dst_addr,
                          uint16_t *src_port,
                          uint16_t *dst_port,
                          uint32_t *seq_num) {
    if (!packet_data || packet_len < sizeof(struct iphdr)) {
        return -1;
    }

    const struct iphdr *ip_header = (const struct iphdr *)packet_data;

    // Verificar versão IP
    if (ip_header->version == 4) {  // IPv4
        *src_addr = *(struct in_addr*)&ip_header->saddr;
        *dst_addr = *(struct in_addr*)&ip_header->daddr;
        *protocol = ip_header->protocol;

        // Verificar tamanho mínimo
        if (packet_len < ip_header->ihl * 4) {
            return -1;
        }

        const uint8_t *transport_header = packet_data + (ip_header->ihl * 4);
        uint32_t transport_len = packet_len - (ip_header->ihl * 4);

        // Extrair informações específicas do protocolo
        if (*protocol == IPPROTO_TCP && transport_len >= sizeof(struct tcphdr)) {
            const struct tcphdr *tcp = (const struct tcphdr *)transport_header;
            *src_port = ntohs(tcp->source);
            *dst_port = ntohs(tcp->dest);
            *seq_num = ntohl(tcp->seq);
            return 0;
        }
        else if (*protocol == IPPROTO_UDP && transport_len >= sizeof(struct udphdr)) {
            const struct udphdr *udp = (const struct udphdr *)transport_header;
            *src_port = ntohs(udp->source);
            *dst_port = ntohs(udp->dest);
            *seq_num = 0;  // UDP não tem número de sequência
            return 0;
        }
        else if (*protocol == IPPROTO_ICMP && transport_len >= sizeof(struct icmphdr)) {
            const struct icmphdr *icmp = (const struct icmphdr *)transport_header;
            *src_port = 0;  // ICMP não usa portas
            *dst_port = 0;
            *seq_num = icmp->un.echo.sequence;  // Para Echo Request/Reply
            return 0;
        }
    }
    // Suporte para IPv6 pode ser adicionado aqui

    return -1;  // Protocolo não suportado ou formato inválido
}