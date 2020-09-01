zephyr_include_directories(.)

# Enable GNU extensions support. This is required to allow the
# use of various de facto standard functions, such as `strnlen`.
#target_compile_definitions(app PRIVATE _GNU_SOURCE)

#target_compile_definitions(app PRIVATE CONFIG_NET_SOCKETS_POSIX_NAMES=1)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/cJSON.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dscp.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_api.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_auth.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_client_api.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_error.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_locale.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_main.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_sctp.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_server_api.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_tcp.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_time.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_udp.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/iperf_util.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/net.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tcp_info.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/timer.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/units.c)