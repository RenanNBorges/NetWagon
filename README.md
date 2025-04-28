# NetWagon #
### Construtor de Pacotes de Rede e Injetor de Trafego com medidor de latencia
**NetWagon** é uma ferramenta para gerar e injetar pacotes de rede a partir de templates definidos em arquivos JSON. Ela pode criar arquivos `.pcap` e realizar injeções de pacotes na rede.

NetWagon e uma ferramente que pode criar pacotes de rede personalizados para:
* IPV4 e IV6
* Protocolos ICMP, TCP, UDP

Com possibilidade de definir:
- IPs e Portas de origem e Destino
- Flags TCP
- Seq Num
- ICMP Code
-  ICMP Type
-  Payload

Apenas com o uso de um arquivo JSON com chave-valor.


## Requisitos

Antes de compilar o projeto, você precisa instalar as seguintes bibliotecas no seu sistema:

- **CMake** (>= 3.10)
- **libpcap** (biblioteca para captura e injeção de pacotes)
- **jansson** (biblioteca para manipulação de arquivos JSON)

### Instalação das dependências no Ubuntu/Debian

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libpcap-dev libjansson-dev
```


Compilação
Clone o repositório e compile o projeto:

```bash
Copiar
Editar
git clone <URL_DO_REPOSITORIO>
cd NetWagon
mkdir build
cd build
cmake ..
make
```
Isso irá gerar dois executáveis dentro do diretório ```build/bin/```:
```
./generator

./netwagon
```
Instalação
Após a compilação, você pode instalar o projeto no seu sistema:

```bash
sudo make install
```
Isso irá instalar os binários generator e netwagon no diretório ```/usr/local/bin/```.

Utilização
1. Gerar Arquivo PCAP
   O programa generator cria um arquivo .pcap a partir de um arquivo JSON contendo os templates de pacotes.

Sintaxe:

```bash
generator <templates.json> [output.pcap]
```
Exemplos:

Gerar um output.pcap padrão:

```bash
./generator templates.json
```
Gerar um arquivo .pcap com nome específico:

```bash
generator templates.json custom_output.pcap
```
Opções:

-h ou --help: Exibe a ajuda.

Descrição dos parâmetros:

<templates.json>: Caminho para o arquivo de templates em JSON.

[output.pcap]: (Opcional) Nome do arquivo de saída. Se omitido, será output.pcap.

### Template JSON:
```json
[
{
"protocol_family":       "ipv4",
"transport_protocol":    "tcp",
"src_ip":                "192.168.1.100",
"dst_ip":                "192.168.1.1",
"src_port":              45678,
"dst_port":              80,
"tcp_seq":               1000,
"tcp_ack_seq":           0,
"tcp_flags":             2,
"payload":               "Hello TCP!",
"packet_count":          3
},
{
"protocol_family":       "ipv4",
"transport_protocol":    "udp",
"src_ip":                "192.168.1.100",
"dst_ip":                "192.168.1.1",
"src_port":              53123,
"dst_port":              2000,
"payload":               "Hello UDP!",
"packet_count":          5
},
{
"protocol_family":       "ipv6",
"transport_protocol":    "icmp",
"src_ip":                "2001:db8::1",
"dst_ip":                "2001:db8::2",
"icmp_type":             128,
"icmp_code":             0,
"payload":               "Ping IPv6!",
"packet_count":          2
}]
```
2. Injeção de Pacotes
[TODO]
