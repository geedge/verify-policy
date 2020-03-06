if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CPACK_PACKAGE_NAME "verify-policy-debug")
else()
    set(CPACK_PACKAGE_NAME "verify-policy")
endif()

message(STATUS "Package: ${CPACK_PACKAGE_NAME}")

set(CPACK_PACKAGE_VENDOR "MESASOFT")
set(CPACK_PACKAGE_VERSION_MAJOR "${VERIFY_POLIC_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${VERIFY_POLIC_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${VERIFY_POLIC_VERSION_PATCH}.${TARGET_DESCRIBE}")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
message(STATUS "VERSION: ${VERIFY_POLIC_VERSION_MAJOR}")

# RPM Build
set(CPACK_GENERATOR "RPM")
set(CPACK_RPM_AUTO_GENERATED_FILE_NAME ON)
set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
set(CPACK_RPM_PACKAGE_AUTOREQPROV "no")
set(CPACK_RPM_PACKAGE_RELEASE_DIST on)
set(CPACK_RPM_DEBUGINFO_PACKAGE on)
set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE ${CMAKE_SOURCE_DIR}/cmake/PreInstall.in)
#set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${CMAKE_SOURCE_DIR}/cmake/PostInstall.in)
#set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE ${CMAKE_SOURCE_DIR}/cmake/PostUninstall.in)
#set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE ${CMAKE_SOURCE_DIR}/cmake/PreUninstall.in)

set(CMAKE_INSTALL_PREFIX "/home/tsg/verify-policy")
set(CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX /home/tsg)

install(PROGRAMS build/platform/verify-policy DESTINATION ./bin)
install(DIRECTORY ./conf DESTINATION ./)
install(DIRECTORY ./resource DESTINATION ./)

install(FILES script/verify-policy.service DESTINATION /usr/lib/systemd/system/)

# Must uninstall the debug package before install release package
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CPACK_RPM_PACKAGE_CONFLICTS "verify-policy")
else()
    set(CPACK_RPM_PACKAGE_CONFLICTS "verify-policy-debug")
endif()

# setup %config(noreplace)
set(CPACK_RPM_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/conf/verify_policy.conf"
			                 "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/resource/table_info_proxy.conf"
                           "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/resource/table_info_security.conf")
include(CPack)
