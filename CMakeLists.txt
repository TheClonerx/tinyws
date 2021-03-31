cmake_minimum_required(VERSION 3.19)
project(tinyws LANGUAGES C)

option(ENABLE_WARNINGS ON)

find_package(OpenSSL REQUIRED)

add_library(tinyws SHARED)
target_include_directories(tinyws PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_sources(tinyws PRIVATE ${CMAKE_SOURCE_DIR}/src/tinyws.c)
target_compile_options(tinyws PRIVATE
    $<$<BOOL:ENABLE_WARNINGS>:
        $<$<C_COMPILER_ID:AppleClang,Clang,GNU>:-Wall -Wextra>
        $<$<C_COMPILER_ID:MSVC>:/W4>
    >
)
target_link_libraries(tinyws PRIVATE OpenSSL::Crypto OpenSSL::SSL)

add_library(tinyws_a STATIC)
target_include_directories(tinyws_a PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_sources(tinyws_a PRIVATE ${CMAKE_SOURCE_DIR}/src/tinyws.c)
target_compile_options(tinyws_a PRIVATE
    $<$<BOOL:ENABLE_WARNINGS>:
        $<$<C_COMPILER_ID:AppleClang,Clang,GNU>:-Wall -Wextra>
        $<$<C_COMPILER_ID:MSVC>:/W4>
    >
)
target_link_libraries(tinyws_a PRIVATE OpenSSL::Crypto OpenSSL::SSL)
