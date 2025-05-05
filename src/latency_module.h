#ifndef LATENCY_MODULE_H
#define LATENCY_MODULE_H

#include <pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

#define MAX_PACKETS 10000000  // ajustar conforme necessidade

// Estrutura de marcação no payload
#pragma pack(push, 1)
typedef struct {
    uint32_t seq;
    uint64_t ts_sec;
    uint64_t ts_nsec;
} latency_hdr_t;
#pragma pack(pop)

// Tabela de timestamps de envio (prealocada)
extern latency_hdr_t *send_table;

// Contadores e estatísticas
extern uint64_t received_count;
extern pthread_mutex_t stats_mutex;

// Inicializa o módulo de medição
int latency_module_init(pcap_t *out_handle, pcap_t *in_handle, uint32_t total_pkts);
// Inicia as threads de envio e recepção
int latency_module_start();
// Aguarda término
void latency_module_join();
// Limpa recursos
void latency_module_cleanup();

#endif // LATENCY_MODULE_H
