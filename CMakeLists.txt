cmake_minimum_required (VERSION 2.8)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/)

project (print_pcap)

set (VERSION_MAJOR 1)
set (VERSION_MINOR 0)

set (SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
set (INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set (APP_NAME print_pcap)

set (CMAKE_BUILD_TYPE RELEASE)

include(cmake/FindPCAP.cmake)

include_directories(SOURCE_DIR)
include_directories(INCLUDE_DIR)

set(SOURCES
	${SOURCE_DIR}/main.cpp
	${SOURCE_DIR}/pcap_parser.cpp
	${SOURCE_DIR}/ipv4_filter.cpp
	${SOURCE_DIR}/port_filter.cpp
)

find_package(PCAP REQUIRED)
include_directories(${PCAP_INCLUDES})
add_compile_options(-std=c++11)
add_definitions(-Wall -O2)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARIES})





