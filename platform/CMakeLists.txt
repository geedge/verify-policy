add_executable(verify-policy src/verify_policy.cpp)

#target_include_directories(verify-policy PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(verify-policy common pangu-http)
target_link_libraries(verify-policy pthread dl
		libevent-static
		MESA_handle_logger
		MESA_prof_load
		cjson
		MESA_htable 
		MESA_field_stat)

