if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CPACK_PACKAGE_NAME "verify-policy-debug")
else()
    set(CPACK_PACKAGE_NAME "verify-policy")
endif()


set(CPACK_PACKAGE_VENDOR "MESASOFT")
set(CMAKE_INSTALL_PREFIX "/opt/tsg/verify-policy")
set(CPACK_PACKAGE_VERSION_MAJOR "${VERIFY_POLICY_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${VERIFY_POLICY_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${VERIFY_POLICY_VERSION_PATCH}.${TARGET_DESCRIBE}")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

# RPM Build
set(CPACK_GENERATOR "RPM")
set(CPACK_RPM_AUTO_GENERATED_FILE_NAME ON)
set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
set(CPACK_RPM_PACKAGE_AUTOREQPROV "no")
set(CPACK_RPM_PACKAGE_RELEASE_DIST on)
set(CPACK_RPM_DEBUGINFO_PACKAGE on)
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${CMAKE_SOURCE_DIR}/cmake/PostInstall.in)
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE ${CMAKE_SOURCE_DIR}/cmake/PostUninstall.in)
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE ${CMAKE_SOURCE_DIR}/cmake/PreUninstall.in)

set(CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX /opt/tsg)

install(PROGRAMS build/platform/verify-policy DESTINATION ./bin)
install(FILES ./conf/verify_policy.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/conf)
install(DIRECTORY ./resource DESTINATION ${CMAKE_INSTALL_PREFIX}/)

install(FILES script/service/verify-policy.service DESTINATION /usr/lib/systemd/system/)
install(FILES script/tmpfiles/verify_policy.conf DESTINATION /usr/lib/tmpfiles.d/)
install(FILES script/service/service_override_memsw_limit.conf DESTINATION /usr/lib/systemd/system/verify-policy.service.d/)

# Must uninstall the debug package before install release package
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CPACK_RPM_PACKAGE_CONFLICTS "verify-policy")
else()
    set(CPACK_RPM_PACKAGE_CONFLICTS "verify-policy-debug")
endif()

# setup %config(noreplace)
set(CPACK_RPM_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/conf/verify_policy.conf"
			                 "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/resource/table_info.conf")
include(CPack)
