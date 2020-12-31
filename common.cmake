###############################################################
#*【项目】CA
#*【描述】
#*【作者】hongchunhua
#*【时间】2020.07.22
###############################################################

#设定编译参数
if (DEFINED CLANG)
	SET (CMAKE_C_COMPILER             "/usr/bin/clang")
	SET (CMAKE_C_FLAGS                "-Wall -std=c99")
	SET (CMAKE_C_FLAGS_DEBUG          "-g")
	SET (CMAKE_C_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
	SET (CMAKE_C_FLAGS_RELEASE        "-O4 -DNDEBUG")
	SET (CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")

	SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
	SET (CMAKE_CXX_FLAGS                "-Wall")
	SET (CMAKE_CXX_FLAGS_DEBUG          "-g")
	SET (CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
	SET (CMAKE_CXX_FLAGS_RELEASE        "-O4 -DNDEBUG")
	SET (CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")

	SET (CMAKE_AR      "/usr/bin/llvm-ar")
	SET (CMAKE_LINKER  "/usr/bin/llvm-ld")
	SET (CMAKE_NM      "/usr/bin/llvm-nm")
	SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump")
	SET (CMAKE_RANLIB  "/usr/bin/llvm-ranlib")
else()
	set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wextra -Wall -g -ggdb")
	set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -Wextra -O3 -Wall")
	set(CMAKE_C_FLAGS_DEBUG "$ENV{CFLAGS} -O0 -std=c99 -fstack-check -Wextra -Wall -Wshadow -Wpointer-arith -g -ggdb3 -Werror -Wdeclaration-after-statement")
	set(CMAKE_C_FLAGS_RELEASE "$ENV{CFLAGS} -O3 -std=c99 -fstack-check -Wextra -Wshadow -Wpointer-arith -Wall")

	if (CMAKE_BUILD_TYPE STREQUAL Release)
		message("NOTE: project to build on [Release] version.")
		set(CMAKE_BUILD_TYPE "Release")
		set(DEBUG_FLAG ${CMAKE_C_FLAGS_RELEASE})
	else()
		message("WARNING: project to build on [Debug] version.")
		set(CMAKE_BUILD_TYPE "Debug")
		set(DEBUG_FLAG ${CMAKE_C_FLAGS_DEBUG})
	endif()
	SET(CA_WARNINGS_SETTING "-Wno-missing-field-initializers -Wunreachable-code -Wredundant-decls -finline-functions -Wno-deprecated -fno-omit-frame-pointer -Wno-unused-parameter -Wno-deprecated-declarations -Wno-unused-function -Wno-unused-variable")
	SET(C_CPP_FLAGS_ "${C_CPP_FLAGS_} -DPIC -fPIC ${DEBUG_FLAG} -D_GNU_SOURCE -DUSE_COMMON_LIB ${OS_FLAG} ${CA_WARNINGS_SETTING}")

	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_CPP_FLAGS_}")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_CPP_FLAGS_}")
endif()

