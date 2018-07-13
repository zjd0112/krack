CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(krack)

option (Is_Client "Generate client" ON)
option (Is_AP "Generate AP" ON)

SET(CMAKE_CXX_COMPILER "g++")
SET(CMAKE_CXX_FLAGS "-std=c++11 -g")
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)

if (Is_Client)
    ADD_EXECUTABLE(
        Client
        ${PROJECT_SOURCE_DIR}/src/client.cpp
        ${PROJECT_SOURCE_DIR}/src/tcp_client.cpp
        ${PROJECT_SOURCE_DIR}/src/rander.cpp
    )
endif (Is_Client)

if (Is_AP)
    ADD_EXECUTABLE(
        AP
        ${PROJECT_SOURCE_DIR}/src/ap.cpp
        ${PROJECT_SOURCE_DIR}/src/tcp_server.cpp
        ${PROJECT_SOURCE_DIR}/src/rander.cpp
        ${PROJECT_SOURCE_DIR}/src/jsoncpp.cpp
    )
endif (Is_AP)

