// main.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "generator/packet.h"
#include "generator/pcap_writer.h"
#include "generator/reader.h"
#include "generator/txrx.h"

static void print_usage(const char *prog) {
    printf("Usage: %s <templates.json> <iface_in> <iface_out> [output.pcap] [timeout_ms]\n", prog);
    printf("  <templates.json>   JSON template file\n");
    printf("  <iface_in>         Interface de captura (RX)\n");
    printf("  <iface_out>        Interface de envio (TX)\n");
    printf("  [output.pcap]      Opcional: filename para gravar pcap\n");
    printf("  [timeout_ms]       Opcional: timeout RX em ms (default=5000)\n");
    printf("Options:\n");
    printf("  -h, --help         Exibe esta ajuda e sai\n");
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    const char *json_file     = argv[1];
    const char *iface_in      = argv[2];
    const char *iface_out     = argv[3];
    const char *output_pcap   = (argc >= 5) ? argv[4] : NULL;
    uint32_t timeout_ms       = 5000;
    if (argc >= 6) {
        timeout_ms = (uint32_t)atoi(argv[5]);
        if (timeout_ms == 0) timeout_ms = 5000;
    }

    // 1) Cria lista e carrega templates
    packet_list_t *list = create_packet_list();
    if (!list) {
        fprintf(stderr, "Erro: não foi possível criar packet list\n");
        return EXIT_FAILURE;
    }
    if (load_templates_from_json(json_file, list) != 0) {
        fprintf(stderr, "Erro ao carregar JSON '%s'\n", json_file);
        free_packet_list(list);
        return EXIT_FAILURE;
    }

    // 2) Se pediu pcap de saída, escreve os pacotes
    if (output_pcap) {
        pcap_dumper_t *dumper = open_pcap_file(output_pcap, 65535, DLT_EN10MB);
        if (!dumper) {
            fprintf(stderr, "Erro criando pcap '%s'\n", output_pcap);
            free_packet_list(list);
            return EXIT_FAILURE;
        }
        int n = write_packet_list_to_pcap(dumper, list);
        printf("Gravou %d pacotes em '%s'\n", n, output_pcap);
        close_pcap_file(dumper);
    }

    // 3) Executa teste TX/RX com timeout e relatório de perda
    printf("Iniciando teste TX/RX: send iface='%s', recv iface='%s', timeout=%ums\n",
           iface_out, iface_in, timeout_ms);
    int rc = txrx_run(list, iface_out, iface_in, timeout_ms);
    if (rc != 0) {
        fprintf(stderr, "Erro durante TX/RX (rc=%d)\n", rc);
        free_packet_list(list);
        return EXIT_FAILURE;
    }

    // 4) Finaliza
    free_packet_list(list);
    return EXIT_SUCCESS;
}
