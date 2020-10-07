# 定义编译的基础环境
cmake_minimum_required(VERSION 2.8)
set(CMAKE_VERBOSE_MAKEFILE on )
add_compile_options(-std=c99 -Wall)

# 启动调试
# set(CMAKE_BUILD_TYPE Debug)

# 给出工程名字
project(sm2)
include_directories(${CMAKE_JS_INC})

################################方法2
# 定义动态链接库
aux_source_directory("./SM2/" DIRSRCS)
add_library(${PROJECT_NAME} SHARED ${DIRSRCS} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

# 链接
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,1073741824")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} ssl crypto)

###############################方法1
# 定义了sm2lib库的生成
# aux_source_directory("./SM2/" DIRSRCS)
# add_library(sm2lib SHARED ${DIRSRCS})

# 定义了动态链接库的生成
# file(GLOB SOURCE_FILES "SM2/sm2_node.cpp")
# add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
# set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")


# 进行了链接
# target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} sm2lib ssl crypto)