###############################################################
#*【项目】CA
#*【描述】
#*【作者】hongchunhua
#*【时间】2020.07.22
###############################################################

cmake_minimum_required(VERSION 3.0)
project(app_project)

set(CA_APP_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
set(CA_APP_PATH "${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory("${CA_APP_PATH}/cafs-tools")
add_subdirectory("${CA_APP_PATH}/server_mds")
add_subdirectory("${CA_APP_PATH}/server_pfile")

