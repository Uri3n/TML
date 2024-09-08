cmake_minimum_required(VERSION 3.28)
project(tml)

set(CMAKE_CXX_STANDARD 20)

option(BUILD_LIB_SHARED "Build as a shared library." OFF)
option(BUILD_LIB_STATIC "Build as a static library." OFF)
option(BUILD_EXECUTABLE "For debug/testing only." ON)

set(TML_SOURCE_FILES
    src/main.cpp
    src/exception.cpp
    src/utility.cpp
    src/handle.cpp
    src/output_device.cpp
    include/tml.hpp
    include/tml_internal.hpp
    src/process.cpp
)

message(STATUS "Cmake: starting compilation.")

if(BUILD_LIB_SHARED)
    if(BUILD_LIB_STATIC OR BUILD_EXECUTABLE)
        message(FATAL_ERROR "Multiple build options specified.")
    endif()
    message("Building as: shared library.")
    add_library(tml SHARED ${TML_SOURCE_FILES})
    target_compile_definitions(tml PRIVATE TML_BUILD_LIB_SHARED)

elseif(BUILD_LIB_STATIC)
    if(BUILD_LIB_SHARED OR BUILD_EXECUTABLE)
        message(FATAL_ERROR "Multiple build options specified.")
    endif()
    message("Building as: static library.")
    add_library(tml STATIC ${TML_SOURCE_FILES})
    target_compile_definitions(tml PRIVATE TML_BUILD_LIB_STATIC)

elseif(BUILD_EXECUTABLE)
    if(BUILD_LIB_SHARED OR BUILD_LIB_STATIC)
        message(FATAL_ERROR "Multiple build options specified.")
    endif()
    message("Building as: Executable.")
    add_executable(tml ${TML_SOURCE_FILES})
    target_compile_definitions(tml PRIVATE TML_BUILD_EXECUTABLE)

else()
    message(FATAL_ERROR "No build option specified.")
endif()

target_include_directories(tml PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
