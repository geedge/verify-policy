add_library(policy_scan src/policy_scan.cpp)
target_include_directories(policy_scan PUBLIC ${CMAKE_CURRENT_LIST_DIR}/incluce)
target_link_libraries(policy_scan PUBLIC common pthread cjson maatframe) 



