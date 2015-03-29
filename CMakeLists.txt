cmake_minimum_required(VERSION 2.8)
cmake_policy(SET CMP0015 NEW)

# Project Definition
project(odhcpd C)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")


add_definitions(-D_GNU_SOURCE -Wall -Werror -Wextra)

if (${EXT_CER_ID})
	add_definitions(-DEXT_CER_ID=${EXT_CER_ID})
endif(${EXT_CER_ID})

if(${UBUS})
	add_definitions(-DWITH_UBUS)
	set(EXT_SRC ${EXT_SRC} src/ubus.c)
	set(EXT_LINK ${EXT_LINK} ubus)
endif(${UBUS})

add_executable(odhcpd src/odhcpd.c src/config.c src/router.c src/dhcpv6.c src/ndp.c src/dhcpv6-ia.c src/dhcpv4.c ${EXT_SRC})
target_link_libraries(odhcpd resolv ubox uci ${EXT_LINK})

# Installation
install(TARGETS odhcpd DESTINATION sbin/)


# Packaging information
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Steven Barth <steven@midlink.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "odhcpd")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)

SET(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")

include(CPack)

