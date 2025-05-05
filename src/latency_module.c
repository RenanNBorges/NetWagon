#include "latency_module.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static pcap_t *handle_out;
static pcap_t *handle_in;
static uint32_t total_packets;

latency_hdr_t *send_table = NULL;
uint64_t received_count = 0;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t tid_send;
pthread_t tid_recv;

// Thread de envio
static void *send_thread(void *arg) {
    uint32_t seq = 0;
    struct timespec ts;
    uint8_t buffer[1500];  // ajustar MTU
    size_t hdr_len = sizeof(latency_hdr_t);

    while (seq < total_packets) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        latency_hdr_t hdr;
        hdr.seq = htonl(seq);
        hdr.ts_sec  = htobe64(ts.tv_sec);
        hdr.ts_nsec = htobe64(ts.tv_nsec);
        memcpy(buffer, &hdr, hdr_len);
        memset(buffer + hdr_len, 0xab, 100);
        send_table[seq] = hdr;
        if (pcap_sendpacket(handle_out, buffer, hdr_len + 100) != 0) {
            fprintf(stderr, "Erro no envio pkt %u: %s\n", seq, pcap_geterr(handle_out));
        }
        seq++;
    }
    return NULL;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    size_t offset = 14 + 20 + 8; // ajuste conforme headers
    const latency_hdr_t *hdr = (const latency_hdr_t *)(packet + offset);
    uint32_t seq = ntohl(hdr->seq);

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t sent_sec  = be64toh(hdr->ts_sec);
    uint64_t sent_nsec = be64toh(hdr->ts_nsec);
    int64_t delta_sec  = now.tv_sec  - sent_sec;
    int64_t delta_nsec = now.tv_nsec - sent_nsec;
    double rtt_us = (delta_sec * 1e6) + (delta_nsec / 1e3);

    pthread_mutex_lock(&stats_mutex);
    received_count++;
    printf("seq=%u RTT=%.2f us\n", seq, rtt_us);
    pthread_mutex_unlock(&stats_mutex);
}

// Thread de recepção
static void *recv_thread(void *arg) {
    pcap_loop(handle_in, total_packets, packet_handler, NULL);
    return NULL;
}

int latency_module_init(pcap_t *out_h, pcap_t *in_h, uint32_t total_pkts) {
    handle_out = out_h;
    handle_in  = in_h;
    total_packets = total_pkts;
    send_table = calloc(total_packets, sizeof(latency_hdr_t));
    return (send_table) ? 0 : -1;
}

int latency_module_start() {
    if (pthread_create(&tid_send, NULL, send_thread, NULL) != 0) return -1;
    if (pthread_create(&tid_recv, NULL, recv_thread, NULL) != 0) return -1;
    return 0;
}

void latency_module_join() {
    pthread_join(tid_send, NULL);
    pthread_join(tid_recv, NULL);
}

void latency_module_cleanup() {
    if (send_table) free(send_table);
}
