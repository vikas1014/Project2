cmake_minimum_required(VERSION 3.14)
project(jwks_server)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include(FetchContent)

# Fetch httplib
FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.11.3
)
FetchContent_MakeAvailable(httplib)

# Fetch jwt-cpp
FetchContent_Declare(
  jwt_cpp
  GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
  GIT_TAG v0.5.1
)
FetchContent_MakeAvailable(jwt_cpp)

# Fetch GoogleTest
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

add_executable(jwks_server Main.cpp)
add_executable(jwks_tests test.cpp)

target_include_directories(jwks_server PRIVATE
    ${jwt_cpp_SOURCE_DIR}/include
    ${httplib_SOURCE_DIR}
)

target_include_directories(jwks_tests PRIVATE
    ${jwt_cpp_SOURCE_DIR}/include
    ${httplib_SOURCE_DIR}
)

target_link_libraries(jwks_server PRIVATE OpenSSL::SSL OpenSSL::Crypto sqlite3)
target_link_libraries(jwks_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto httplib::httplib jwt_cpp::jwt_cpp sqlite3 gtest gtest_main)

enable_testing()
add_test(NAME JWKSServerTests COMMAND jwks_tests)
