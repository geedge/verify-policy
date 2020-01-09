add_library(common src/verify_policy_logging.cpp)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(common PUBLIC MESA_handle_logger libevent-static)

