cmake_minimum_required(VERSION 3.16)

project(logger VERSION 0.1.0 LANGUAGES CXX)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME}
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} INTERFACE format flags)
target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_20)

add_subdirectory(lib)