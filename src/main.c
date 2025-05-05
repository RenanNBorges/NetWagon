// main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>

#include "../include/generator/reader.h"       // load_templates_from_json()
#include "../include/generator/pcap_writer.h"  // open_pcap_file(), write_packet_list_to_pcap(), close_pcap_file()
#include "../include/generator/packet.h"       // packet_list_t, free_packet_list()
#include "../include/injector/txrx.h"

static void print_usage(const char *prog) {
    printf("Usage: %s -f <templates.json> -r <iface_in> -s <iface_out> [-o <output.pcap>] [-t <timeout_ms>]\n", prog);
    printf("  -f <file>   JSON template file (obrigatório)\n");
    printf("  -r <iface>  Interface de captura (RX) (obrigatório)\n");
    printf("  -s <iface>  Interface de envio (TX) (obrigatório)\n");
    printf("  -o <file>   Opcional: filename para gravar pcap\n");
    printf("  -t <ms>     Opcional: timeout RX em milissegundos (default=5000)\n");
    printf("  -h          Exibe esta ajuda e sai\n");
}

int main(int argc, char *argv[]) {
    char *json_file = NULL;
    char *iface_in = NULL;
    char *iface_out = NULL;
    char *output_pcap = NULL;
    uint32_t timeout_ms = 5000;
    int opt;

    while ((opt = getopt(argc, argv, "f:r:s:o:t:h")) != -1) {
        switch (opt) {
            case 'f': json_file = optarg; break;
            case 'r': iface_in = optarg; break;
            case 's': iface_out = optarg; break;
            case 'o': output_pcap = optarg; break;
            case 't': timeout_ms = (uint32_t)atoi(optarg);
                      if (timeout_ms == 0) timeout_ms = 5000;
                      break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    if (!json_file || !iface_in || !iface_out) {
        fprintf(stderr, "Erro: parâmetros obrigatórios faltando.\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
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

    // 2) PCAP opcional
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

    // 3) Teste TX/RX
    printf("Iniciando TX/RX: TX iface='%s', RX iface='%s', timeout=%ums\n",
           iface_out, iface_in, timeout_ms);
    int rc = txrx_run(list, iface_out, iface_in, timeout_ms);
    if (rc != 0) {
        fprintf(stderr, "Erro durante TX/RX (rc=%d)\n", rc);
        free_packet_list(list);
        return EXIT_FAILURE;
    }

    // 4) Cleanup
    free_packet_list(list);
    return EXIT_SUCCESS;
}
