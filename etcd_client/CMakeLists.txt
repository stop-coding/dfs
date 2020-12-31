cmake_minimum_required(VERSION 3.0)
project(etcd-client)

#设定源码
set(MODULE_NAME "etcd-cli")
set(CAFS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(CAFS_OPEN_SRC ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(ETCD_SRC ${CMAKE_CURRENT_SOURCE_DIR}/)
set(ETCD_CPP_HEADER ${ETCD_SRC})
set(ETCD_APIV3_CPP /usr/local/include/etcd)
set(ETCD_CPP_PB ${ETCD_APIV3_CPP}/proto)
set(ETCD_CPP_PB_API ${ETCD_APIV3_CPP}/proto/gen/proto)
set(JSONCPP_HEADER /usr/local/include/json)

set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wextra -Wall -g -ggdb -std=c++11 -fPIC")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -Wextra -O0 -Wall -g -ggdb -std=c++11 -fPIC")

file(GLOB_RECURSE CFILES "${CMAKE_SOURCE_DIR}/*.c")
SET_SOURCE_FILES_PROPERTIES(${CFILES} PROPERTIES LANGUAGE CXX )

set(SOURCE_FILES "")
aux_source_directory(${ETCD_SRC} SOURCE_FILES)

#设定头文件路径
include_directories(${ETCD_SRC} 
                    ${ETCD_CPP_PB}
                    ${ETCD_CPP_PB_API}
                    ${JSONCPP_HEADER}
                    ${ETCD_CPP_HEADER})

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)           #设置库文件的输出目录

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})

#添加依赖项子目录
add_library(${MODULE_NAME} SHARED ${SOURCE_FILES})

install (TARGETS ${MODULE_NAME} DESTINATION lib)
install (FILES ${CMAKE_CURRENT_SOURCE_DIR}/etcd-client.hpp
               DESTINATION include/etcd)
