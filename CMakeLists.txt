cmake_minimum_required(VERSION 2.8.8)
project(Steam++)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

find_package(Protobuf REQUIRED)
find_package(CryptoPP REQUIRED)
find_package(LibArchive REQUIRED)

if(NOT DEFINED STEAMKIT)
  message(FATAL_ERROR "STEAMKIT needs to be defined using -DSTEAMKIT=<path to the steamkit sources>")
endif()
set(PROTOBUF_IMPORT_DIRS ${STEAMKIT}/Resources/Protobufs)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS
	${PROTOBUF_IMPORT_DIRS}/steamclient/steammessages_clientserver.proto
	${PROTOBUF_IMPORT_DIRS}/steamclient/steammessages_clientserver_2.proto
	${PROTOBUF_IMPORT_DIRS}/steamclient/steammessages_base.proto
	${PROTOBUF_IMPORT_DIRS}/steamclient/encrypted_app_ticket.proto
)

set(CMAKE_CXX_FLAGS " -Wall -Wextra -pedantic -std=c++11 ${CMAKE_CXX_FLAGS}")

include_directories(
	${PROTOBUF_INCLUDE_DIRS}
	${CRYPTOPP_INCLUDE_DIR}
	${LibArchive_INCLUDE_DIRS}
	${CMAKE_CURRENT_BINARY_DIR}
)

add_library(steam++
	steam++.cpp
	cmclient.cpp
	handlers.cpp
	${PROTO_SRCS}
)

target_link_libraries(steam++
	${PROTOBUF_LIBRARIES}
	${CRYPTOPP_LIBRARIES}
	${LibArchive_LIBRARIES}
)
