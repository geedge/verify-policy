# CMakeFiles for 3rd vendor library

include(ExternalProject)

### Libevent 2.1.8
ExternalProject_Add(libevent PREFIX libevent
        URL ${CMAKE_CURRENT_SOURCE_DIR}/libevent-2.1.8-stable.tar.gz
        URL_MD5 f3eeaed018542963b7d2416ef1135ecc
        CONFIGURE_COMMAND PKG_CONFIG_PATH=${OPENSSL_PKGCONFIG_PATH}
		                  ./configure --prefix=<INSTALL_DIR> --disable-shared --disable-samples
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(libevent INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(libevent-static STATIC IMPORTED GLOBAL)
add_dependencies(libevent-static libevent)
set_property(TARGET libevent-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libevent.a)
set_property(TARGET libevent-static PROPERTY IMPORTED_INTERFACE_LINK_LIBRARIES pthread crypto)
set_property(TARGET libevent-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

### cJSON
ExternalProject_Add(cJSON PREFIX cJSON
        URL ${CMAKE_CURRENT_SOURCE_DIR}/cJSON-1.7.7.tar.gz
        URL_MD5 715009c99728bf81d6c97352718650ff
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
				   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
				   -DBUILD_SHARED_AND_STATIC_LIBS=1)

ExternalProject_Get_Property(cJSON INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(cjson SHARED IMPORTED GLOBAL)
add_dependencies(cjson cJSON)
set_property(TARGET cjson PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/libcjson.a)
set_property(TARGET cjson PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

#### GoogleTest
ExternalProject_Add(googletest PREFIX googletest
        URL ${CMAKE_CURRENT_SOURCE_DIR}/googletest-release-1.8.0.tar.gz
        URL_MD5 16877098823401d1bf2ed7891d7dce36
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(googletest INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(gtest STATIC IMPORTED GLOBAL)
add_dependencies(gtest googletest)
set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libgtest.a)
set_property(TARGET gtest PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET gtest PROPERTY INTERFACE_LINK_LIBRARIES pthread)

add_library(gmock STATIC IMPORTED GLOBAL)
add_dependencies(gmock googletest)
set_property(TARGET gmock PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libgmock.a)
set_property(TARGET gmock PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)


### MESA Framework
# Consider the MESA Framework is installed in the system. We declare a imported target instead of
# ExternalProject target. we may retrive the MESAFramework source code from git.mesalab.cn and
# compile staticly to TFE binarys in the future.

set(MESA_FRAMEWORK_LIB_DIR /opt/MESA/lib)
set(MESA_FRAMEWORK_INCLUDE_DIR /opt/MESA/include)

add_library(MESA_handle_logger SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_handle_logger PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_handle_logger.so)
set_property(TARGET MESA_handle_logger PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(MESA_prof_load SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_prof_load PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_prof_load.so)
set_property(TARGET MESA_prof_load PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(maatframe SHARED IMPORTED GLOBAL)
set_property(TARGET maatframe PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libmaatframe.so)
set_property(TARGET maatframe PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

### pcre2
ExternalProject_Add(pcre2 PREFIX pcre2
        URL ${CMAKE_CURRENT_SOURCE_DIR}/pcre2-10.32.tar.gz
        URL_MD5 a660db882ff171e6a0de5fb1decd5ff5
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(pcre2 INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(pcre2-static STATIC IMPORTED GLOBAL)
add_dependencies(pcre2-static pcre2)
set_property(TARGET pcre2-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libpcre2-8.a)
set_property(TARGET pcre2-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

