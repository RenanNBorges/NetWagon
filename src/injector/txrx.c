//
// Created by rnborges on 05/05/25.
//

#include "../../include/generator/txrx.h"
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct {
    packet_list_t *list;
    const char    *iface_send;
    const char    *iface_recv;
    uint32_t       timeout_ms;

    uint32_t       total_pkts;
    uint32_t      *send_times_ms;  // timestamp (ms) de cada envio
    int            *recv_flags;    // 0 = não recebido, 1 = recebido

    pthread_mutex_t lock;
    pthread_cond_t  cond_all_recv;
    int             rx_done;
} txrx_ctx_t;

// utilitário para obter timestamp em milissegundos
static uint32_t now_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
}

// TX thread: envia todos os pacotes e preenche send_times_ms
static void *thread_tx(void *arg) {
    txrx_ctx_t *ctx = (txrx_ctx_t*)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(ctx->iface_send, BUFSIZ, 0, 1, errbuf);
    if (!pcap) {
        fprintf(stderr, "TX: não foi possível abrir interface '%s': %s\n",
                ctx->iface_send, errbuf);
        return NULL;
    }

    packet_t *pkt = ctx->list->head;
    uint32_t idx = 0;
    while (pkt) {
        uint32_t t0 = now_ms();
        if (pcap_sendpacket(pcap, pkt->data, pkt->length) != 0) {
            fprintf(stderr, "TX[%u]: falha ao enviar: %s\n",
                    idx, pcap_geterr(pcap));
        }
        pthread_mutex_lock(&ctx->lock);
        ctx->send_times_ms[idx] = t0;
        pthread_mutex_unlock(&ctx->lock);

        pkt = pkt->next;
        idx++;
        usleep(1000);  // ajuste: intervalo entre envios, se desejar
    }

    pcap_close(pcap);
    return NULL;
}

// RX thread: captura pacotes, extrai ID do payload e marca recv_flags[id-1]
// quando todos recebidos ou timeout ocorre, sinaliza condição
static void *thread_rx(void *arg) {
    txrx_ctx_t *ctx = (txrx_ctx_t*)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(ctx->iface_recv, BUFSIZ, 1, 100, errbuf);
    if (!pcap) {
        fprintf(stderr, "RX: não foi possível abrir interface '%s': %s\n",
                ctx->iface_recv, errbuf);
        return NULL;
    }

    uint32_t start_wait = 0;
    int done = 0;
    while (!done) {
        struct pcap_pkthdr *hdr;
        const u_char *data;
        int res = pcap_next_ex(pcap, &hdr, &data);
        if (res == 1) {
            // Salta ethernet + IP/TCP/UDP cabeçalhos até o payload
            const u_char *payload = data + /* offset exato depende do seu add_ethernet_header + ip+tcp*/ 14 + 20 + 20;
            // Encontre o separador '|'
            char *sep = memchr((void*)payload, '|', hdr->caplen);
            if (sep) {
                int id = atoi((char*)payload);
                if (id >= 1 && id <= (int)ctx->total_pkts) {
                    pthread_mutex_lock(&ctx->lock);
                    if (!ctx->recv_flags[id-1]) {
                        ctx->recv_flags[id-1] = 1;
                        // sinaliza caso tenha recebido o último pendente
                        int all = 1;
                        for (uint32_t i = 0; i < ctx->total_pkts; i++) {
                            if (!ctx->recv_flags[i]) { all = 0; break; }
                        }
                        if (all) {
                            done = 1;
                            pthread_cond_signal(&ctx->cond_all_recv);
                        }
                    }
                    pthread_mutex_unlock(&ctx->lock);
                }
            }
        }
        // inicia contagem de timeout após o primeiro recv ou logo após TX
        if (!start_wait) {
            start_wait = now_ms();
        }
        if (start_wait && now_ms() - start_wait >= ctx->timeout_ms) {
            done = 1;
            pthread_cond_signal(&ctx->cond_all_recv);
        }
    }

    pcap_close(pcap);
    return NULL;
}

int txrx_run(packet_list_t *list,
             const char *iface_send,
             const char *iface_recv,
             uint32_t timeout_ms) {
    if (!list || list->count == 0) {
        fprintf(stderr, "txrx_run: lista vazia\n");
        return -1;
    }

    txrx_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.list        = list;
    ctx.iface_send  = iface_send;
    ctx.iface_recv  = iface_recv;
    ctx.timeout_ms  = timeout_ms;
    ctx.total_pkts  = list->count;
    ctx.send_times_ms = calloc(ctx.total_pkts, sizeof(uint32_t));
    ctx.recv_flags   = calloc(ctx.total_pkts, sizeof(int));
    pthread_mutex_init(&ctx.lock, NULL);
    pthread_cond_init(&ctx.cond_all_recv, NULL);

    pthread_t th_tx, th_rx;
    pthread_create(&th_rx, NULL, thread_rx, &ctx);
    usleep(100000);  // garante que RX comece antes de TX
    pthread_create(&th_tx, NULL, thread_tx, &ctx);

    // espera RX terminar (todos recebidos ou timeout)
    pthread_mutex_lock(&ctx.lock);
    pthread_cond_wait(&ctx.cond_all_recv, &ctx.lock);
    pthread_mutex_unlock(&ctx.lock);

    // limpa threads
    pthread_join(th_tx, NULL);
    pthread_join(th_rx, NULL);

    // computa estatísticas
    uint32_t recv_cnt = 0;
    for (uint32_t i = 0; i < ctx.total_pkts; i++) {
        if (ctx.recv_flags[i]) recv_cnt++;
    }
    uint32_t loss = ctx.total_pkts - recv_cnt;
    double loss_rate = (double)loss / ctx.total_pkts * 100.0;

    printf("TX/RX concluído: enviados=%u, recebidos=%u, perdidos=%u, taxa de perda=%.2f%%\n",
           ctx.total_pkts, recv_cnt, loss, loss_rate);

    free(ctx.send_times_ms);
    free(ctx.recv_flags);
    pthread_mutex_destroy(&ctx.lock);
    pthread_cond_destroy(&ctx.cond_all_recv);
    return 0;
}
