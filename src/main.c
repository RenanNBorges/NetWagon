#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/generator/reader.h"
#include "../include/generator/pcap_writer.h"
#include "../include/generator/packet.h"

#define DEFAULT_NUM_THREADS 4

static void print_usage(const char *prog) {
    printf("Usage: %s <templates.json> [output.pcap]\n", prog);
    printf("  <templates.json>   JSON template file\n");
    printf("  [output.pcap]      Optional output pcap filename (default: output.pcap)\n");
    printf("Options:\n");
    printf("  -h, --help         Display this help and exit\n");
    printf("Threads fixed to %d (no overrides).\n", DEFAULT_NUM_THREADS);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    const char *json_file   = argv[1];
    const char *output_file = (argc >= 3) ? argv[2] : "output.pcap";

    int num_threads = DEFAULT_NUM_THREADS;
    int use_threads = (num_threads > 1);

    packet_list_t *list = create_packet_list();
    if (!list) {
        fprintf(stderr, "Failed to create packet list\n");
        return 1;
    }

    load_templates_from_json(json_file, list);

    pcap_dumper_t *dumper = open_pcap_file(output_file, 65535, DLT_EN10MB);
    if (!dumper) {
        fprintf(stderr, "Error creating pcap '%s'\n", output_file);
        free_packet_list(list);
        return 1;
    }

    int written = write_packet_list_to_pcap(dumper, list);
    printf("Wrote %d packets to '%s'\n", written, output_file);

    close_pcap_file(dumper);
    free_packet_list(list);
    return 0;
}
