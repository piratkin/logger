cmake_minimum_required(
  VERSION 3.16)

project(liblogger
  VERSION 0.1.0
  LANGUAGES C CXX)

set(DEFAULT_APP_NAME ${CMAKE_PROJECT_NAME})
set(DEFAULT_ERROR_LEVEL warn)
set(DEFAULT_SIZE_LIMIT 1048576)
set(DEFAULT_DEPTH_LIMIT 10)
set(DEFAULT_SYSOUT_FLAG 1)
set(DEFAULT_SYSLOG_FLAG 0)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/logger.h.in 
  ${CMAKE_CURRENT_BINARY_DIR}/logger.h)

add_library(
  ${PROJECT_NAME}
  INTERFACE)

target_include_directories(
  ${PROJECT_NAME}
  INTERFACE
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(
  ${PROJECT_NAME}
  INTERFACE
  libformat)
  
target_compile_features(
  ${PROJECT_NAME}
  INTERFACE
  cxx_std_20)