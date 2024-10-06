cmake_minimum_required(VERSION 3.23)

project(ci LANGUAGES CXX)

find_package(wwa_tlsserverhelpers CONFIG REQUIRED)
add_executable(ci test.cpp)
target_compile_features(ci PRIVATE cxx_std_20)
target_link_libraries(ci PRIVATE wwa::TLSServerHelpers)
