#ifndef READER_H
#define READER_H

#include "packet.h"

/**
 * Carrega um arquivo JSON contendo uma lista de templates de pacotes e
 * adiciona os pacotes criados à lista fornecida.
 *
 * @param filename     Caminho para o arquivo .json
 * @param list         Lista onde os pacotes serão inseridos
 */
void load_templates_from_json(const char *filename,
                              packet_list_t *list);

#endif // READER_H