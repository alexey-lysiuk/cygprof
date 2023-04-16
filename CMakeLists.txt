cmake_minimum_required(VERSION 3.1)

project(cygprof)

add_library(cygprof cygprof.cpp)
set_property(TARGET cygprof PROPERTY CXX_STANDARD 17)
install(TARGETS cygprof)

add_executable(cygprof-test cygprof-test.cpp)
set_property(TARGET cygprof-test PROPERTY CXX_STANDARD 17)
target_compile_options(cygprof-test PRIVATE -finstrument-functions)
target_link_libraries(cygprof-test PRIVATE cygprof)
