zephyr_include_directories(.)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/icmp_ping.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/icmp_ping_shell.c)