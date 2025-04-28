
#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include <pcap/pcap.h>
#include "packet.h"

/**
 * Opens a new PCAP file for writing
 * @param filename Path to the output file
 * @param snaplen Maximum length of captured packets (typically 65535)
 * @param network Network type (typically DLT_RAW for raw IP packets)
 * @return Handle to the PCAP file or NULL on error
 */
pcap_dumper_t* open_pcap_file(const char *filename, int snaplen, int network);

/**
 * Writes a single packet to a PCAP file
 * @param dumper Handle to the PCAP file
 * @param packet Packet to write
 * @return 0 on success, -1 on failure
 */
int write_packet_to_pcap(pcap_dumper_t *dumper, packet_t *packet);

/**
 * Writes all packets in a list to a PCAP file
 * @param dumper Handle to the PCAP file
 * @param list List of packets to write
 * @return Number of packets written, or -1 on failure
 */
int write_packet_list_to_pcap(pcap_dumper_t *dumper, packet_list_t *list);

/**
 * Closes a PCAP file
 * @param dumper Handle to the PCAP file
 */
void close_pcap_file(pcap_dumper_t *dumper);
#endif //PCAP_WRITER_H
