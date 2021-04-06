target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/curl)
add_subdirectory_ifdef(CONFIG_MOSH_CURL_LIB lib)
add_subdirectory_ifdef(CONFIG_MOSH_CURL_TOOL tool)

