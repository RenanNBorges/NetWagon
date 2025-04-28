cmake_minimum_required(VERSION 3.10)
project(NetWagon C)

set(CMAKE_C_STANDARD 11)

# ------------------------------------------------------------
# 1) Encontrar dependências via pkg-config
# ------------------------------------------------------------
find_package(PkgConfig REQUIRED)

# libpcap
pkg_check_modules(PCAP REQUIRED libpcap)
# jansson
pkg_check_modules(JANSSON REQUIRED jansson)

# ------------------------------------------------------------
# 2) Diretórios de inclusão
# ------------------------------------------------------------
include_directories(
        ${PCAP_INCLUDE_DIRS}
        ${JANSSON_INCLUDE_DIRS}
        # seu diretório de includes público
        ${CMAKE_SOURCE_DIR}/include
)

# ------------------------------------------------------------
# 3) Fontes do projeto
# ------------------------------------------------------------
set(SOURCES
        src/generator/packet.c
        src/generator/pcap_writer.c
        src/generator/proto_icmp.c
        src/generator/proto_tcp.c
        src/generator/proto_udp.c
        src/generator/reader.c
        src/main.c
)

# ------------------------------------------------------------
# 4) Executável
# ------------------------------------------------------------
add_executable(netwagon ${SOURCES})

# ------------------------------------------------------------
# 5) Linkagem das bibliotecas
# ------------------------------------------------------------
target_link_libraries(netwagon
        PRIVATE
        ${PCAP_LIBRARIES}
        ${JANSSON_LIBRARIES}
)

# Se você quiser linkar também via link_directories (não estritamente necessário,
# pois pkg-config já passa os -L), poderia fazer:
# link_directories(${PCAP_LIBRARY_DIRS} ${JANSSON_LIBRARY_DIRS})

# ------------------------------------------------------------
# 6) Copiar variáveis de flags (opcional, mas recomendado)
# ------------------------------------------------------------
# Garante que se o pkg-config para PCAP ou Jansson definir flags extra (-D, -fPIC,
# etc), elas sejam propagadas:
add_compile_options(${PCAP_CFLAGS_OTHER} ${JANSSON_CFLAGS_OTHER})
add_link_options(${PCAP_LDFLAGS_OTHER} ${JANSSON_LDFLAGS_OTHER})

# ------------------------------------------------------------
# 7) Instalação
# ------------------------------------------------------------
install(TARGETS netwagon DESTINATION bin)
