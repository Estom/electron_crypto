cmake_minimum_required(VERSION 2.8)
set(CMAKE_VERBOSE_MAKEFILE on )
add_compile_options(-std=c99 -Wall)

project(sm2)

aux_source_directory(. DIRSRCS)

add_executable(sm2 ${DIRSRCS})


target_link_libraries(sm2 ssl crypto)
