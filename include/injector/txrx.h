#ifndef TXRX_H
#define TXRX_H

#include <stdint.h>
#include "../generator/packet.h"


typedef struct {
    packet_list_t *list;
    const char    *iface_send;
    const char    *iface_recv;
    uint32_t       timeout_ms;

    uint32_t      total_pkts;
    uint32_t     *send_times_ms;
    int          *recv_flags;

    pthread_mutex_t lock;
    pthread_cond_t  cond_all_recv;
} txrx_ctx_t;

    /// Configura e dispara o teste de TX/RX.
    /// @param list        lista de pacotes (deve conter payloads prefixados com ID|…)
    /// @param iface_send  interface para envio (ex.: "eth0")
    /// @param iface_recv  interface para captura (ex.: "eth0" ou outra)
    /// @param timeout_ms  tempo máximo de espera, em milissegundos, após o último envio
    /// @return 0 em sucesso, !=0 em erro
    int txrx_run(packet_list_t *list,
                 const char *iface_send,
                 const char *iface_recv,
                 uint32_t timeout_ms);



#endif // TXRX_H
