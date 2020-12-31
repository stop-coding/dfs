###############################################################
#*【项目】CA
#*【描述】
#*【作者】hongchunhua
#*【时间】2020.07.22
###############################################################

cmake_minimum_required(VERSION 3.0)
project(cafs)
 
#宏定义
add_definitions(-D USR_FLAG)
add_definitions(-D CLANG)

include("${CMAKE_CURRENT_SOURCE_DIR}/common.cmake")

set(COM_ROOT_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
set(CA_ROOT_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
set(CA_OPENSRC_PATH "${CA_ROOT_PATH}/third_party")
set(CA_APP_PATH "${CA_ROOT_PATH}/app")

#设定源码
set(CA_FS ${COM_ROOT_PATH}/cafs)
set(CA_INCLUDE ${COM_ROOT_PATH}/inc)
set(CA_SRC ${COM_ROOT_PATH}/src)
set(CA_SRC_COMMON ${CA_SRC}/common)
set(CA_SRC_FS ${CA_SRC}/file_system)
set(CA_SRC_PRT ${CA_SRC}/PRT)
set(CA_SRC_CON ${CA_SRC}/connection)
set(CA_OPEN_SRC_INI ${CA_OPENSRC_PATH}/iniparser)
set(CA_KLIB_PATH ${CA_OPENSRC_PATH}/klib)
set(CA_MDS ${CA_SRC}/mds)
set(CA_PFILE ${CA_SRC}/pfile)
set(CA_PRT ${CA_SRC}/prt)
set(CA_CONFIG ${CA_SRC}/config)
set(CA_CFG ${COM_ROOT_PATH}/config)
set(CA_SRC_ETCD ${COM_ROOT_PATH}/etcd_client)

#file(GLOB_RECURSE CFILES "${CMAKE_SOURCE_DIR}/*.c")
#SET_SOURCE_FILES_PROPERTIES(${CFILES} PROPERTIES LANGUAGE CXX )

#设置输出路径
SET(EXECUTABLE_OUTPUT_PATH ${COM_ROOT_PATH}/${CMAKE_BUILD_TYPE}_build_out/bin)       #设置可执行文件的输出目录
SET(LIBRARY_OUTPUT_PATH ${COM_ROOT_PATH}/${CMAKE_BUILD_TYPE}_build_out/lib)           #设置库文件的输出目录

set(SOURCE_FILES "")
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SOURCE_FILES)
aux_source_directory(${CA_SRC_COMMON} SOURCE_FILES)
aux_source_directory(${CA_SRC_FS} SOURCE_FILES)
aux_source_directory(${CA_SRC_PRT} SOURCE_FILES)
aux_source_directory(${CA_SRC_CON} SOURCE_FILES)
aux_source_directory(${CA_OPEN_SRC_INI} SOURCE_FILES)
aux_source_directory(${CA_MDS} SOURCE_FILES)
aux_source_directory(${CA_PRT} SOURCE_FILES)
aux_source_directory(${CA_CONFIG} SOURCE_FILES)
aux_source_directory(${CA_PFILE} SOURCE_FILES)

#设定头文件路径
include_directories(${CMAKE_CURRENT_SOURCE_DIR} 
                    ${CA_KLIB_PATH} 
                    ${CA_INCLUDE} 
                    ${CA_SRC_COMMON} 
                    ${CA_SRC_FS} 
                    ${CA_SRC_PRT} 
                    ${CA_SRC_CON} 
                    ${CA_OPEN_SRC_INI} 
                    ${CA_MDS} 
                    ${CA_CONFIG} 
                    ${CA_PRT}
					${CA_PFILE}
					${CA_SRC_ETCD}
					${CA_FS})
 
 
#设定链接库的路径（一般使用第三方非系统目录下的库）
set(LINK_LIB_PATH ${COM_ROOT_PATH}/lib)
LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH} ${LINK_LIB_PATH})
 
 
#动态库
add_library(cafs SHARED ${SOURCE_FILES})
target_link_libraries(cafs -letcd-cli -letcd-cpp-api -lgrpc++ -lgrpc -lboost_system -lprotobuf 
                    -ljsoncpp -lcpprest -larpc -lfsmsg -lnuma -ldl -lrt -lpthread)

if(EXISTS ${CMAKE_INSTALL_PREFIX})
message("CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}")
INSTALL(FILES ${LIBRARY_OUTPUT_PATH}/libcafs.so DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
INSTALL(FILES ${LINK_LIB_PATH}/libarpc.so DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
INSTALL(FILES ${LINK_LIB_PATH}/libfsmsg.so DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
INSTALL(FILES ${CA_FS}/libcafs.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
INSTALL(FILES ${CA_FS}/libcafs.h DESTINATION /usr/include/)
INSTALL(FILES ${CA_CFG}/cafs.conf DESTINATION /etc/cafs/)
else()
message("it could set : cmake CMAKE_INSTALL_PREFIX=/usr/local ../")
INSTALL(FILES ${LIBRARY_OUTPUT_PATH}/libcafs.so DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
INSTALL(FILES ${LINK_LIB_PATH}/libarpc.so DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
INSTALL(FILES ${LINK_LIB_PATH}/libfsmsg.so DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
INSTALL(FILES ${CA_FS}/libcafs.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
INSTALL(FILES ${CA_FS}/libcafs.h DESTINATION /usr/include/)
INSTALL(FILES ${CA_CFG}/cafs.conf DESTINATION /etc/cafs/)
endif()

#子项目
#add_subdirectory("${CA_APP_PATH}/cafs-tools")
#add_subdirectory("${CA_APP_PATH}/server_mds")
#add_subdirectory("${CA_APP_PATH}/server_pfile")
add_subdirectory("${CA_APP_PATH}/testcase")
