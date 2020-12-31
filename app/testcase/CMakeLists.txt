cmake_minimum_required(VERSION 3.0)
project(testcase)


include("${CMAKE_CURRENT_SOURCE_DIR}/../../common.cmake")

#设定源码
set(CA_ROOT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(CA_OPENSRC_PATH "${CA_ROOT_PATH}/open_src")

SET(EXECUTABLE_OUTPUT_PATH ${CA_ROOT_PATH}/${CMAKE_BUILD_TYPE}_build_out/bin)       #设置可执行文件的输出目录
SET(LIBRARY_OUTPUT_PATH ${CA_ROOT_PATH}/${CMAKE_BUILD_TYPE}_build_out/lib)           #设置库文件的输出目录

set(CA_FS ${COM_ROOT_PATH}/cafs)
set(CA_SRC_COMMON ${CA_SRC}/common)
set(CA_SRC_ETCD ${CA_OPENSRC_PATH}/etcd-client)

message(${CA_SRC_ETCD})

set(SOURCE_FILES "")
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SOURCE_FILES)
aux_source_directory(${CA_SRC_COMMON} SOURCE_FILES)

#设定头文件路径
include_directories(${CA_FS} 
                    ${CA_INCLUDE} 
                    ${CA_SRC_ETCD}/etcd
                    ${CA_SRC_COMMON})
 
 
#设定链接库的路径（一般使用第三方非系统目录下的库）
set(LINK_LIB_PATH ${DPENDENCY_LIB_PATH})
LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH} ${LINK_LIB_PATH})
 
 
#添加依赖项子目录
 
#生成可执行文件
add_executable(testcase ${SOURCE_FILES})
target_link_libraries(testcase -lcafs)

add_dependencies(testcase cafs)
