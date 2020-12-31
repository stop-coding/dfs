cmake_minimum_required(VERSION 2.8)
project(server_mds)

set(CA_ROOT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(CA_OPENSRC_PATH "${CA_ROOT_PATH}/third_party")
set(CA_SRC "${CA_ROOT_PATH}/src")

set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wextra -Wall -g -ggdb3 -std=c++11 -fPIC")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -Wextra -O0 -Wall -g -ggdb -std=c++11 -fPIC")

file(GLOB_RECURSE CFILES "${CMAKE_SOURCE_DIR}/*.c")
SET_SOURCE_FILES_PROPERTIES(${CFILES} PROPERTIES LANGUAGE CXX )

#设置输出路径
SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/build_out/bin)       #设置可执行文件的输出目录
SET(LIBRARY_OUTPUT_PATH ${CA_ROOT_PATH}/lib)           #设置库文件的输出目录

#设定源码
set(CA_SRC_COMMON ${CA_SRC}/common)
set(CA_MDS ${CA_SRC}/mds)
set(CA_INCLUDE ${CA_ROOT_PATH}/inc)
set(CA_SRC_CON ${CA_SRC}/connection)
set(LEVELDB_INC ${CA_ROOT_PATH}/third_party)
set(JSON_SRC ${CA_ROOT_PATH}/third_party/jsoncpp/include)

set(SOURCE_FILES "${CA_MDS}/cafs_mds_msg.c")
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SOURCE_FILES)
aux_source_directory(${CA_SRC_COMMON} SOURCE_FILES)
#设定头文件路径
include_directories(${CA_MDS}
                    ${JSON_SRC}
                    ${CA_INCLUDE}
                    ${LEVELDB_INC} 
                    ${CA_SRC_COMMON})

set(LINK_LIB_PATH ${DPENDENCY_LIB_PATH})
LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH} ${LINK_LIB_PATH})
#添加依赖项子目录
 
#生成可执行文件
add_executable(server_mds ${SOURCE_FILES})
target_link_libraries(server_mds librocksdb.a -ljsoncpp -larpc -lfsmsg -lnuma -ldl -lrt -lpthread)

if(EXISTS ${CMAKE_INSTALL_PREFIX})
message("CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}")
INSTALL(TARGETS server_mds DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
else()
message("it could set : cmake CMAKE_INSTALL_PREFIX=/usr/local ../")
INSTALL(TARGETS server_mds DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
endif()
