cmake_minimum_required(VERSION 2.8)
set(CMAKE_VERBOSE_MAKEFILE on )
add_compile_options(-std=c99 -Wall)
set(CMAKE_BUILD_TYPE Debug)

project(pcA)

aux_source_directory(. DIRSRCS)

add_executable(pcA ${DIRSRCS})

target_link_libraries(pcA ssl crypto)
