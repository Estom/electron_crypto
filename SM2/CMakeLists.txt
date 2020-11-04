cmake_minimum_required(VERSION 2.8)
set(CMAKE_VERBOSE_MAKEFILE on )
add_compile_options(-std=c99 -Wall)
set(CMAKE_BUILD_TYPE Debug)

project(pcB)

aux_source_directory(. DIRSRCS)

add_executable(pcB ${DIRSRCS})

target_link_libraries(pcB ssl crypto)
