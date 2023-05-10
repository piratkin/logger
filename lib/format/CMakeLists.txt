project(format)

add_subdirectory(fmt)

add_library(${PROJECT_NAME} ALIAS fmt)
