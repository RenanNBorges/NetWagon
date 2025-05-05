cmake_minimum_required(VERSION 3.10)
project(NetWagon C)

set(CMAKE_C_STANDARD 11)
find_package(PkgConfig REQUIRED)

# libpcap
pkg_check_modules(PCAP REQUIRED libpcap)
# jansson
pkg_check_modules(JANSSON REQUIRED jansson)

include_directories(
        ${PCAP_INCLUDE_DIRS}
        ${JANSSON_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/include
)

# Generator target
set(GENERATOR_SOURCES
            src/generator/packet.c
            src/generator/pcap_writer.c
            src/generator/proto_icmp.c
            src/generator/proto_tcp.c
            src/generator/proto_udp.c
            src/generator/reader.c
            src/generator/generator.c
    )
add_executable(generator ${GENERATOR_SOURCES})
target_link_libraries(generator PRIVATE ${PCAP_LIBRARIES} ${JANSSON_LIBRARIES})

# Injector target
set(INJECTOR_SOURCES
        src/generator/packet.c
        src/generator/pcap_writer.c
        src/generator/proto_icmp.c
        src/generator/proto_tcp.c
        src/generator/proto_udp.c
        src/generator/reader.c
        src/main.c
        src/latency_module.c
        src/latency_module.h
)
add_executable(netwagon ${INJECTOR_SOURCES})
target_link_libraries(netwagon PRIVATE ${PCAP_LIBRARIES} ${JANSSON_LIBRARIES})

add_compile_options(${PCAP_CFLAGS_OTHER} ${JANSSON_CFLAGS_OTHER})
add_link_options(${PCAP_LDFLAGS_OTHER} ${JANSSON_LDFLAGS_OTHER})

install(TARGETS generator netwagon DESTINATION bin)