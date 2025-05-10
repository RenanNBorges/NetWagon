
#include "../include/injector/txrx.h"
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

// obtém timestamp em ms
static uint32_t now_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

// thread de envio
static void *thread_tx(void *arg) {
    txrx_ctx_t *ctx = arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_live(ctx->iface_send, BUFSIZ, 0, 1, errbuf);
    if (!pc) {
        fprintf(stderr, "TX: não abriu '%s': %s\n", ctx->iface_send, errbuf);
        return NULL;
    }

    packet_t *pkt = ctx->list->head;
    for (uint32_t idx = 0; pkt; pkt = pkt->next, idx++) {
        uint32_t t0 = now_ms();
        if (pcap_sendpacket(pc, pkt->data, pkt->length) != 0) {
            fprintf(stderr, "TX[%u]: falha: %s\n", idx, pcap_geterr(pc));
        }
        pthread_mutex_lock(&ctx->lock);
        ctx->send_times_ms[idx] = t0;
        pthread_mutex_unlock(&ctx->lock);
        usleep(1000);  // pequenas pausas para não atropelar a interface
    }

    pcap_close(pc);
    return NULL;
}

// thread de captura e correlação
static void *thread_rx(void *arg) {
    txrx_ctx_t *ctx = arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_live(ctx->iface_recv, BUFSIZ, 1, 100, errbuf);
    if (!pc) {
        fprintf(stderr, "RX: não abriu '%s': %s\n", ctx->iface_recv, errbuf);
        return NULL;
    }

    uint32_t start_wait = 0;
    int done = 0;
    while (!done) {
        struct pcap_pkthdr *hdr;
        const u_char *pkt = NULL;
        int res = pcap_next_ex(pc, &hdr, &pkt);
        if (res == 1 && hdr->caplen >= 14 + 20) {
            // 1) Cabeçalho Ethernet fixo (14 bytes)
            // 2) Cabeçalho IPv4: IHL varia
            uint8_t  ihl_words = pkt[14] & 0x0F;
            size_t   ihl       = ihl_words * 4;
            if (hdr->caplen < 14 + ihl) continue;

            // 3) Protocolo de transporte
            uint8_t proto = pkt[14 + 9];
            size_t  th_len = 0;
            if (proto == IPPROTO_TCP) {
                // TCP Data Offset em palavras de 32 bits
                uint8_t doff_words = (pkt[14 + ihl + 12] >> 4) & 0x0F;
                th_len = doff_words * 4;
            } else if (proto == IPPROTO_UDP || proto == IPPROTO_ICMP) {
                th_len = 8;
            } else {
                continue;
            }

            // 4) Offset total do payload
            size_t offset = 14 + ihl + th_len;
            if (hdr->caplen <= offset) continue;
            size_t payload_len = hdr->caplen - offset;
            const u_char *payload = pkt + offset;

            // 5) Procura ID no payload
            char *sep = memchr((void*)payload, '|', payload_len);
            if (!sep) continue;
            int id = atoi((char*)payload);
            if (id < 1 || id > (int)ctx->total_pkts) continue;

            // 6) Marca como recebido
            pthread_mutex_lock(&ctx->lock);
            if (!ctx->recv_flags[id-1]) {
                ctx->recv_flags[id-1] = 1;
                // verifica se todos chegaram
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

        // timeout global
        if (!start_wait) start_wait = now_ms();
        if (now_ms() - start_wait >= ctx->timeout_ms) {
            done = 1;
            pthread_cond_signal(&ctx->cond_all_recv);
        }
    }

    pcap_close(pc);
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
    ctx.recv_flags    = calloc(ctx.total_pkts, sizeof(int));
    pthread_mutex_init(&ctx.lock, NULL);
    pthread_cond_init(&ctx.cond_all_recv, NULL);

    // inicia threads RX e TX
    pthread_t th_rx, th_tx;
    pthread_create(&th_rx, NULL, thread_rx, &ctx);
    usleep(100000);  // garante RX ativo antes de TX começar
    pthread_create(&th_tx, NULL, thread_tx, &ctx);

    // aguarda sinal de conclusão (todos ou timeout)
    pthread_mutex_lock(&ctx.lock);
    pthread_cond_wait(&ctx.cond_all_recv, &ctx.lock);
    pthread_mutex_unlock(&ctx.lock);

    // finaliza threads
    pthread_join(th_tx, NULL);
    pthread_join(th_rx, NULL);

    // calcula estatísticas
    uint32_t recv_cnt = 0;
    for (uint32_t i = 0; i < ctx.total_pkts; i++) {
        if (ctx.recv_flags[i]) recv_cnt++;
    }
    uint32_t loss = ctx.total_pkts - recv_cnt;
    double loss_rate = (double)loss / ctx.total_pkts * 100.0;
    printf("TX/RX concluído: enviados=%u, recebidos=%u, perdidos=%u, perda=%.2f%%\n",
           ctx.total_pkts, recv_cnt, loss, loss_rate);

    // cleanup
    free(ctx.send_times_ms);
    free(ctx.recv_flags);
    pthread_mutex_destroy(&ctx.lock);
    pthread_cond_destroy(&ctx.cond_all_recv);

    return 0;
}
