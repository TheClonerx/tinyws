cmake_minimum_required(VERSION 3.19)
project(tinyws LANGUAGES C CXX)

add_library(tinyws SHARED)
target_include_directories(tinyws PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_sources(tinyws PRIVATE ${CMAKE_SOURCE_DIR}/src/tinyws.c)

add_library(tinyws_a STATIC)
target_include_directories(tinyws_a PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_sources(tinyws_a PRIVATE ${CMAKE_SOURCE_DIR}/src/tinyws.c)
