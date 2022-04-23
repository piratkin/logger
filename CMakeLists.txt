cmake_minimum_required(
  VERSION 3.16)

project(liblogger 
  VERSION 0.1.0 
  LANGUAGES CXX)

set(DEFAULT_APP_NAME ${CMAKE_PROJECT_NAME})
set(DEFAULT_ERROR_LEVEL warn)
set(DEFAULT_SIZE_LIMIT 1048576)
set(DEFAULT_DEPTH_LIMIT 10)
set(DEFAULT_SYSOUT_FLAG 1)
set(DEFAULT_SYSLOG_FLAG 0)
set(DEFAULT_COLOR_FLAG 1)

set(DEFAULT_NONE_COLOR white)
set(DEFAULT_FATAL_COLOR fuchsia)
set(DEFAULT_ERROR_COLOR orange_red)
set(DEFAULT_WARN_COLOR yellow)
set(DEFAULT_INFO_COLOR lime)
set(DEFAULT_DEBUG_COLOR light_sea_green)
set(DEFAULT_TRACE_COLOR gray)

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