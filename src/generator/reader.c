#include "../../include/generator/reader.h"
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/generator/proto_tcp.h"
#include "../../include/generator/proto_udp.h"
#include "../../include/generator/proto_icmp.h"

int load_templates_from_json(const char *filename,
                             packet_list_t *list) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    if (!root) {
        fprintf(stderr, "Erro ao abrir JSON '%s': %s\n", filename, error.text);
        return 1;
    }
    if (!json_is_array(root)) {
        fprintf(stderr, "Formato inválido: raiz JSON deve ser um array\n");
        json_decref(root);
        return 1;
    }

    uint32_t next_id = 1; // inicializa ID incremental

    size_t idx;
    json_t *obj;
    json_array_foreach(root, idx, obj) {
        const char *family_s = json_string_value(json_object_get(obj, "protocol_family"));
        const char *trans_s  = json_string_value(json_object_get(obj, "transport_protocol"));
        const char *src_ip   = json_string_value(json_object_get(obj, "src_ip"));
        const char *dst_ip   = json_string_value(json_object_get(obj, "dst_ip"));
        int src_port         = (int)json_integer_value(json_object_get(obj, "src_port"));
        int dst_port         = (int)json_integer_value(json_object_get(obj, "dst_port"));
        uint32_t packet_count= (uint32_t)json_integer_value(json_object_get(obj, "packet_count"));

        // Seleciona família de IP
        int af = AF_INET;
        if (family_s && strcmp(family_s, "ipv6") == 0) {
            af = AF_INET6;
        }

        // Seleciona protocolo de transporte
        int proto = IPPROTO_UDP;
        if (trans_s) {
            if (strcmp(trans_s, "tcp") == 0) proto = IPPROTO_TCP;
            else if (strcmp(trans_s, "icmp") == 0) proto = IPPROTO_ICMP;
        }

        // Parâmetros TCP/ICMP (opcionais)
        uint32_t tcp_seq   = (uint32_t)json_integer_value(json_object_get(obj, "tcp_seq"));
        uint32_t tcp_ack   = (uint32_t)json_integer_value(json_object_get(obj, "tcp_ack_seq"));
        uint8_t  tcp_flags = (uint8_t)json_integer_value(json_object_get(obj, "tcp_flags"));
        uint8_t  icmp_type = (uint8_t)json_integer_value(json_object_get(obj, "icmp_type"));
        uint8_t  icmp_code = (uint8_t)json_integer_value(json_object_get(obj, "icmp_code"));

        // Payload original (string)
        const char *pl_str = json_string_value(json_object_get(obj, "payload"));
        size_t pl_size     = pl_str ? strlen(pl_str) : 0;

        for (uint32_t i = 0; i < packet_count; ++i) {
            // --- Monta payload com ID no início ---
            // Reserve espaço para: [ID] + separador + payload original + '\0'
            // Supondo até 10 dígitos de ID; 12 = espaço para "[", "]", "|" e '\0'
            size_t buf_size =  pl_size + 12;
            char *pl_with_id = malloc(buf_size);
            if (!pl_with_id) {
                fprintf(stderr, "Falha ao alocar memória para payload\n");
                json_decref(root);
                return 1;
            }
            // Ex.: "1|Hello TCP!"
            int len = snprintf(pl_with_id,
                               buf_size,
                               "%u|%s",
                               next_id++,
                               pl_str ? pl_str : "");
            if (len < 0 || (size_t)len >= buf_size) {
                fprintf(stderr, "Erro ao formatar payload com ID\n");
                free(pl_with_id);
                json_decref(root);
                return 1;
            }

            // Cria o pacote apropriado
            packet_t *pkt = NULL;
            if (af == AF_INET) {
                switch (proto) {
                    case IPPROTO_TCP:
                        pkt = create_tcp_packet(
                            IP_V4,
                            src_ip, dst_ip,
                            (uint16_t)src_port,
                            (uint16_t)dst_port,
                            tcp_seq, tcp_ack,
                            tcp_flags,
                            pl_with_id, (size_t)len
                        );
                        break;
                    case IPPROTO_UDP:
                        pkt = create_udp_packet(
                            IP_V4,
                            src_ip, dst_ip,
                            (uint16_t)src_port,
                            (uint16_t)dst_port,
                            pl_with_id, (size_t)len
                        );
                        break;
                    case IPPROTO_ICMP:
                        pkt = create_icmp_packet(
                            IP_V4,
                            src_ip, dst_ip,
                            icmp_type, icmp_code,
                            0, 0,
                            pl_with_id, (size_t)len
                        );
                        break;
                }
            } else { // IPv6
                switch (proto) {
                    case IPPROTO_TCP:
                        pkt = create_tcp_packet(
                            IP_V6,
                            src_ip, dst_ip,
                            (uint16_t)src_port,
                            (uint16_t)dst_port,
                            tcp_seq, tcp_ack,
                            tcp_flags,
                            pl_with_id, (size_t)len
                        );
                        break;
                    case IPPROTO_UDP:
                        pkt = create_udp_packet(
                            IP_V6,
                            src_ip, dst_ip,
                            (uint16_t)src_port,
                            (uint16_t)dst_port,
                            pl_with_id, (size_t)len
                        );
                        break;
                    case IPPROTO_ICMP:
                        pkt = create_icmp_packet(
                            IP_V6,
                            src_ip, dst_ip,
                            icmp_type, icmp_code,
                            0, 0,
                            pl_with_id, (size_t)len
                        );
                        break;
                }
            }

            if (pkt) {
                add_packet_to_list(list, pkt);
            }
            free(pl_with_id);
        }
    }

    json_decref(root);
    return 0;
}
