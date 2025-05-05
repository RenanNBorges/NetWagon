#ifndef PACKET_MONITOR_H
#define PACKET_MONITOR_H

#include "../generator/packet.h"
#include <pcap.h>
#include <stdbool.h>

typedef struct {
    uint64_t sent;        // Pacotes enviados
    uint64_t received;    // Pacotes recebidos
    uint64_t lost;        // Pacotes perdidos
    double loss_percent;  // Porcentagem de perda
} packet_stats_t;

// Inicializa o monitor de pacotes
void monitor_init(const char *iface_out, const char *iface_in, bool capture_pcap, const char *pcap_file);

// Envia pacotes da lista através da interface
void monitor_send_packets(packet_list_t *list);

// Aguarda o término da monitoração
void monitor_wait_completion();

// Obtém estatísticas atuais
packet_stats_t monitor_get_stats();

// Finaliza o monitor (libera recursos)
void monitor_cleanup();

#endif // PACKET_MONITOR_H