cmake_minimum_required(VERSION 3.5)

include_directories(${CMAKE_SOURCE_DIR}/common/include)
add_executable(verify_policy_test verify_policy_test.cpp ${CMAKE_SOURCE_DIR}/platform/src/verify_matcher.cpp)
target_link_libraries(verify_policy_test common MESA_prof_load maatframe cjson gtest)

set(CMAKE_BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(TEST_RUN_DIR ${CMAKE_BUILD_DIR}/test)
file(COPY ${CMAKE_SOURCE_DIR}/resource DESTINATION ${TEST_RUN_DIR})
file(COPY ${CMAKE_SOURCE_DIR}/conf DESTINATION ${TEST_RUN_DIR})
file(COPY ${CMAKE_SOURCE_DIR}/test/resource/VerifyPolicyHit.json DESTINATION ${TEST_RUN_DIR}/resource)
file(COPY ${CMAKE_SOURCE_DIR}/test/resource/HitPolicyResult.json DESTINATION ${TEST_RUN_DIR}/resource)
file(COPY ${CMAKE_SOURCE_DIR}/test/resource/HitPolicyRequest.json DESTINATION ${TEST_RUN_DIR}/resource)

add_test(NAME UPDATE_MAAT_MODE  COMMAND bash -c "sed -i 's/maat_input_mode=1/maat_input_mode=0/' ${TEST_RUN_DIR}/conf/verify_policy.conf")
add_test(NAME UPDATE_LOG_LEVEL   COMMAND bash -c "sed -i 's/log_level=5/log_level=1/' ${TEST_RUN_DIR}/conf/verify_policy.conf")
add_test(NAME UPDATE_VSYS_NUM   COMMAND bash -c "sed -i '32i load_vsys_num=2' ${TEST_RUN_DIR}/conf/verify_policy.conf")
add_test(NAME UPDATE_START_VSYS   COMMAND bash -c "sed -i '33i load_start_vsys=1' ${TEST_RUN_DIR}/conf/verify_policy.conf")
add_test(NAME UPDATE_JSON_FILE COMMAND bash -c "sed -i 's/json_cfg_file=\\.\\/resource\\/verify-policy\\.json/json_cfg_file=\\.\\/resource\\/VerifyPolicyHit\\.json/' ${TEST_RUN_DIR}/conf/verify_policy.conf")
