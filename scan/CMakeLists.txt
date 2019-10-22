add_library(pangu-http src/pangu_http.cpp)
target_include_directories(pangu-http PUBLIC ${CMAKE_CURRENT_LIST_DIR}/incluce)
target_link_libraries(pangu-http PUBLIC common pthread cjson maatframe) 



