
#include "../../include/generator/pcap_writer.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>

pcap_dumper_t* open_pcap_file(const char *filename, int snaplen, int network) {
    pcap_t *pcap;
    pcap_dumper_t *dumper;

    // Create a dummy pcap_t for the dumper
    pcap = pcap_open_dead(network, snaplen);
    if (pcap == NULL) {
        return NULL;
    }

    // Open the dump file
    dumper = pcap_dump_open(pcap, filename);
    if (dumper == NULL) {
        pcap_close(pcap);
        return NULL;
    }

    return dumper;
}

int write_packet_to_pcap(pcap_dumper_t *dumper, packet_t *packet) {
    struct pcap_pkthdr header;

    if (!dumper || !packet || !packet->data) {
        return -1;
    }

    // Set current time
    gettimeofday(&header.ts, NULL);

    // Set packet length
    header.caplen = packet->length;
    header.len = packet->length;

    // Write the packet
    pcap_dump((u_char *)dumper, &header, packet->data);

    return 0;
}

int write_packet_list_to_pcap(pcap_dumper_t *dumper, packet_list_t *list) {
    packet_t *current;
    int count = 0;

    if (!dumper || !list) {
        return -1;
    }

    current = list->head;
    while (current) {
        if (write_packet_to_pcap(dumper, current) == 0) {
            count++;
        }
        current = current->next;
    }

    return count;
}

void close_pcap_file(pcap_dumper_t *dumper) {
    if (dumper) {
        pcap_dump_close(dumper);
    }
}
