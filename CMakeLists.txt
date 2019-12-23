cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(Socks5-Server LANGUAGES CXX)

add_executable(${PROJECT_NAME} src/main.cpp src/session/client_session.cpp src/session/client_session.hpp src/crypto/crypto.cpp src/crypto/crypto.hpp src/session/server_session.cpp src/session/server_session.hpp src/config/config.hpp)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_EXTENSIONS OFF)

#target_include_directories(${PROJECT_NAME} PRIVATE /usr/local/Cellar/openssl/1.0.2t/include)

find_package(Boost 1.71.0 REQUIRED COMPONENTS chrono coroutine system thread)
target_link_libraries(${PROJECT_NAME} PRIVATE Boost::chrono Boost::coroutine Boost::system Boost::thread)