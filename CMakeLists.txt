# 定义编译的基础环境
cmake_minimum_required(VERSION 2.8)
set(CMAKE_VERBOSE_MAKEFILE on )
add_compile_options(-std=c99 -Wall)

# set(CMAKE_BUILD_TYPE Debug)
# add_definitions(-DNAPI_VERSION=3)
# add_subdirectory(SM2/src)

# project (hello)
# include_directories(${CMAKE_JS_INC})
# file(GLOB SOURCE_FILES "./Hello/hello.cc")
# add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
# set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
# target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})


# 定义了工程名字和包含的文件
project (sm2)
include_directories(${CMAKE_JS_INC} SM2/include)

# 定义了sm2lib库的生成
aux_source_directory("./SM2/src/" DIRSRCS)
add_library(sm2lib SHARED ${DIRSRCS})


# 定义了动态链接库的生成
file(GLOB SOURCE_FILES "SM2/src/sm2_node.cpp")
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

# 进行了链接
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} sm2lib ssl crypto)