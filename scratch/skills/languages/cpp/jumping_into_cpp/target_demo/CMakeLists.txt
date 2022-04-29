cmake_minimum_required(VERSION 3.10)

set (CMAKE_CXX_STANDARD 11)

# set the project name
project(Demonstration)

# find the packages we need
find_package (glog 0.5.0 REQUIRED)



# add the executable
add_executable(Demonstration demo.cpp)

# Link stuff
target_link_libraries (Demonstration glog::glog)