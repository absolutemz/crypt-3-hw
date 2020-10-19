cmake_minimum_required(VERSION 3.17)
project(flat_shamir_protocol)

set(CMAKE_CXX_STANDARD 17)

include_directories(project/include)

add_executable(${PROJECT_NAME} 
        main.cpp
        project/src/split_recover.cpp
        project/src/crypt.cpp)

find_package(OpenSSL REQUIRED)

target_link_libraries(flat_shamir_protocol OpenSSL::SSL)
