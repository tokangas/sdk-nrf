zephyr_include_directories(.)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sock_shell.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sock.c)
