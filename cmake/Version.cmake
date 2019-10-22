
# Using autorevision.sh to generate version information

set(__SOURCE_AUTORESIVISION ${CMAKE_SOURCE_DIR}/autorevision.sh)
set(__AUTORESIVISION ${CMAKE_BINARY_DIR}/autorevision.sh)
set(__VERSION_CACHE ${CMAKE_SOURCE_DIR}/version.txt)
set(__VERSION_CONFIG ${CMAKE_BINARY_DIR}/version.cmake)

file(COPY ${__SOURCE_AUTORESIVISION} DESTINATION ${CMAKE_BINARY_DIR}
	FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
	WORLD_READ WORLD_EXECUTE)

# execute autorevision.sh to generate version information
execute_process(COMMAND ${__AUTORESIVISION} -t cmake -o ${__VERSION_CACHE} OUTPUT_FILE ${__VERSION_CONFIG})
include(${__VERSION_CONFIG})

# extract major, minor, patch version from git tag
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" VERIFY_POLICY_VERSION_MAJOR "${VCS_TAG}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" VERIFY_POLIC_VERSION_MINOR "${VCS_TAG}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" VERIFY_POLIC_VERSION_PATCH "${VCS_TAG}")

if(NOT VERIFY_POLIC_VERSION_MAJOR)
    set(VERIFY_POLIC_VERSION_MAJOR 1)
endif()

if(NOT VERIFY_POLIC_VERSION_MINOR)
    set(VERIFY_POLIC_VERSION_MINOR 0)
endif()

if(NOT VERIFY_POLIC_VERSION_PATCH)
    set(VERIFY_POLIC_VERSION_PATCH 0)
endif()

set(VERIFY_POLIC_VERSION "${VERIFY_POLIC_VERSION_MAJOR}.${VERIFY_POLIC_VERSION_MINOR}.${VERIFY_POLIC_VERSION_PATCH}")

# print information
message(STATUS "Welcome to Verify Policy Engine, Version: ${VERIFY_POLIC_VERSION}")
add_definitions(-DVERIFY_POLIC_VERSION=${VERIFY_POLIC_VERSION})
