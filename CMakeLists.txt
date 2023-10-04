cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 20)

project(psf)

add_library(src
	src/arg.cpp
	src/lock.cpp
)

add_executable(psf src/main.cpp)

include(./cmake/Findsodium.cmake)

include_directories(/usr/local/include)
include_directories(./src)
link_directories(/usr/local/lib)

set_target_properties(psf PROPERTIES OUTPUT_NAME "psf")

target_link_libraries(psf PRIVATE src sodium)

# Install target
if (NOT BIN_INSTALL_DIR)
    set(BIN_INSTALL_DIR bin)
endif ()

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
)
