/* main.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "latency_module.h"    // nosso módulo de medição de RTT
#include "../include/generator/reader.h"
#include "../include/generator/pcap_writer.h"
#include "../include/generator/packet.h"

static void print_usage(const char *prog) {
    printf("Usage: %s <templates.json> <eth_in> <eth_out>\n", prog);
    printf("  <templates.json>   JSON template file\n");
    printf("  <eth_in>           Interface Input (\"none\" para desabilitar captura)\n");
    printf("  <eth_out>          Interface Output\n");
    printf("  [output.pcap]      Optional output pcap filename (default: output.pcap)\n");
    printf("Options:\n");
    printf("  -h, --help         Display this help and exit\n");
}

int main(int argc, char *argv[]) {
    if (argc < 4 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return (argc < 4) ? 1 : 0;
    }

    const char *json_file     = argv[1];
    const char *interface_in  = argv[2];
    const char *interface_out = argv[3];
    const char *output_pcap   = (argc >= 5) ? argv[4] : "output.pcap";

    // 1) Carrega templates e gera lista de pacotes
    packet_list_t *list = create_packet_list();
    if (!list) {
        fprintf(stderr, "Falha ao criar lista de pacotes\n");
        return 1;
    }
    load_templates_from_json(json_file, list);

    // 2) (Opcional) grava em PCAP de saída
    pcap_dumper_t *dumper = open_pcap_file(output_pcap, 65535, DLT_EN10MB);
    if (!dumper) {
        fprintf(stderr, "Erro criando pcap '%s'\n", output_pcap);
        free_packet_list(list);
        return 1;
    }
    int written = write_packet_list_to_pcap(dumper, list);
    printf("Wrote %d packets to '%s'\n", written, output_pcap);
    close_pcap_file(dumper);

    // 3) Abre handles libpcap para envio e captura
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle_out = pcap_open_live(interface_out, BUFSIZ, 1, 1000, errbuf);
    if (!handle_out) {
        fprintf(stderr, "Erro abrindo output '%s': %s\n", interface_out, errbuf);
        free_packet_list(list);
        return 1;
    }

    pcap_t *handle_in = NULL;
    if (strcmp(interface_in, "none") != 0) {
        handle_in = pcap_open_live(interface_in, BUFSIZ, 1, 1000, errbuf);
        if (!handle_in) {
            fprintf(stderr, "Aviso: não foi possível abrir input '%s': %s\n",
                    interface_in, errbuf);
            // prossegue mesmo sem captura
        }
    }

    // 4) Inicializa módulo de latência (aloca tabela, guarda handles)
    if (latency_module_init(handle_out, handle_in, list->count) != 0) {
        fprintf(stderr, "Erro inicializando módulo de latência\n");
        pcap_close(handle_out);
        if (handle_in) pcap_close(handle_in);
        free_packet_list(list);
        return 1;
    }

    // 5) Inicia threads de envio/recepção
    if (latency_module_start() != 0) {
        fprintf(stderr, "Erro iniciando threads de latência\n");
        latency_module_cleanup();
        free_packet_list(list);
        return 1;
    }

    // 6) Aqui você pode fazer outras tarefas ou simplesmente aguardar término.
    //    Se quiser rodar até Ctrl+C, pode usar pause() ou similar.
    printf("Medição de latência em andamento (%u pacotes)...\n", list->count);
    latency_module_join();   // bloqueia até todas threads terminarem

    // 7) Finaliza e libera recursos
    latency_module_cleanup();
    pcap_close(handle_out);
    if (handle_in) pcap_close(handle_in);
    free_packet_list(list);

    printf("Recebidos %lu pacotes de %u enviados\n", received_count, list->count);
    return 0;
}
