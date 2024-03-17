cmake_minimum_required(VERSION 3.16)

project(pinch-example VERSION 1.0.0)

if(PROJECT_IS_TOP_LEVEL)
find_package(pinch REQUIRED)
endif()

add_executable(pinch-example example-1.cpp)
target_link_libraries(pinch-example pinch::pinch)
