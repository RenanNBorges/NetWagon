#ifndef SAVE_METRICS_H
#define SAVE_METRICS_H

#include <stdint.h>
#include <time.h>

/**
 * Salva as métricas de latência em um arquivo CSV com nome gerado automaticamente
 * no formato: latency_metrics_YYYY-MM-DD_HH-MM-SS.csv
 *
 * @param send_timestamp Array com os timestamps de envio
 * @param recv_timestamp Array com os timestamps de recebimento
 * @param total_pkts Número total de pacotes
 * @return 0 em caso de sucesso, -1 em caso de erro
 */
int save_metrics_to_csv(const uint64_t *send_timestamp,
                        const uint64_t *recv_timestamp,
                        uint32_t total_pkts, const struct tm *timeinfo);

#endif /* SAVE_METRICS_H */