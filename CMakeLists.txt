cmake_minimum_required(VERSION 3.10)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)

project(Cerberus VERSION 3.0.0)

set(SOURCES
	src/utils.cpp
	src/cerberus.cpp
	src/main.cpp
)

add_executable(cerberus ${SOURCES})
target_include_directories(cerberus PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(cerberus PRIVATE ${PROJECT_BINARY_DIR})
target_include_directories(cerberus PRIVATE ${PROJECT_BINARY_BIN})
target_include_directories(cerberus PRIVATE /usr/include)

configure_file(config.hpp.in ${PROJECT_BINARY_DIR}/config.hpp)

find_package(OpenSSL REQUIRED)

if (NOT OPENSSL_CRYPTO_LIBRARY OR NOT OPENSSL_SSL_LIBRARY)
	message(FATAL_ERROR "OpenSSL not found")
endif()

target_link_libraries(cerberus PUBLIC OpenSSL::SSL OpenSSL::Crypto argon2)

target_compile_options(cerberus PRIVATE -D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS -fstack-clash-protection -fstack-protector-strong -fcf-protection -O2 -Wall -Wl,-z,relro)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
