#ifndef READER_H
#define READER_H

#include "packet.h"

/**
 * Carrega um arquivo JSON contendo uma lista de templates de pacotes e
 * adiciona os pacotes criados à lista fornecida.
 *
 * @param filename     Caminho para o arquivo .json
 * @param list         Lista onde os pacotes serão inseridos
 * @param use_threads  1 para uso de threads, 0 para sequencial
 * @param num_threads  Número de threads a usar (se use_threads=1)
 */
void load_templates_from_json(const char *filename,
                              packet_list_t *list,
                              int use_threads,
                              int num_threads);

#endif // READER_H