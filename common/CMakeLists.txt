add_library(common src/verify_policy_utils.cpp src/log.c)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(common PUBLIC libevent-static)

