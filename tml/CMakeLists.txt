cmake_minimum_required(VERSION 3.28)
project(tml)

set(CMAKE_CXX_STANDARD 20)

set(TML_SOURCE_FILES
    main.cpp
    tml.hpp
)

add_executable(tml ${TML_SOURCE_FILES})
