zephyr_include_directories(.)

target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ltelc_api.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ltelc_shell.c)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ltelc.c)