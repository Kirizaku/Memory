cmake_minimum_required (VERSION 3.5)

project ("main")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Main executable
add_executable (main "main.cpp" "../memory.cpp" "../memory.h")

# Test target
add_executable(test-target test-target.cpp)

# Test library
add_library(test-library SHARED test-library.cpp)

if(UNIX)
    set_target_properties(test-library PROPERTIES PREFIX "")
endif()
