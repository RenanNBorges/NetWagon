#include "../include/injector/save_metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

/**
 * Cria um diretório se ele não existir
 * @return 0 se bem-sucedido ou se já existir, -1 em caso de erro
 */
static int ensure_directory_exists() {
    struct stat st;

    if (stat("latencies", &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            // Diretório já existe
            return 0;
        } else {
            // Existe, mas não é um diretório
            fprintf(stderr, "Erro: '%s' existe mas não é um diretório\n", "latencies");
            return -1;
        }
    }

    if (mkdir("latencies", 0755) != 0) {
        fprintf(stderr, "Erro ao criar diretório '%s': %s\n",
                "latencies", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Gera um nome de arquivo com timestamp no formato:
 * [directory]/latency_metrics_YYYY-MM-DD_HH-MM-SS.csv
 */
static void generate_filename(char *filename_buffer, const struct tm *timeinfo) {
    char timestamp[32];

    // Formatar timestamp: YYYY-MM-DD_HH-MM-SS
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d_%H-%M-%S", timeinfo);

    // Construir nome completo do arquivo no buffer fornecido
    snprintf(filename_buffer, 64, "%s/latency_%s.csv",
             "latencies", timestamp);
}

int save_metrics_to_csv(const uint64_t *send_timestamp,
                        const uint64_t *recv_timestamp,
                        uint32_t total_pkts, const struct tm *timeinfo) {
    // Verificar argumentos
    if (!send_timestamp || !recv_timestamp || total_pkts == 0) {
        fprintf(stderr, "save_metrics_to_csv: argumentos inválidos\n");
        return -1;
    }

    // Garantir que o diretório existe
    if (ensure_directory_exists() != 0) {
        return -1;
    }

    char filename[64];
    generate_filename(filename, timeinfo);

    // Abrir arquivo para escrita
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "save_metrics_to_csv: falha ao abrir arquivo '%s'\n", filename);
        return -1;
    }

    // Escrever cabeçalho
    fprintf(file, "ID,send_timestamp,recv_timestamp\n");

    // Escrever dados
    for (uint32_t i = 0; i < total_pkts; i++) {
        // ID é baseado em 1 (não em 0)
        fprintf(file, "%u,%lu,%lu\n",
                i + 1,
                send_timestamp[i],
                recv_timestamp[i]);
    }

    // Fechar arquivo
    fclose(file);

    printf("Métricas salvas em '%s'\n", filename);

    return 0;
}