cmake_minimum_required(VERSION 3.1)
project(Steam++)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

find_package(Protobuf REQUIRED)
find_package(CryptoPP REQUIRED)
find_package(LibArchive REQUIRED)

set(PROTOBUF_IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/Protobufs)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS
	${PROTOBUF_IMPORT_DIRS}/steam/steammessages_clientserver.proto
	${PROTOBUF_IMPORT_DIRS}/steam/steammessages_clientserver_2.proto
	${PROTOBUF_IMPORT_DIRS}/steam/steammessages_clientserver_login.proto
	${PROTOBUF_IMPORT_DIRS}/steam/steammessages_base.proto
	${PROTOBUF_IMPORT_DIRS}/steam/steammessages_clientserver_friends.proto
	${PROTOBUF_IMPORT_DIRS}/steam/encrypted_app_ticket.proto
)

set(CMAKE_CXX_FLAGS " -Wall ${CMAKE_CXX_FLAGS}")
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	# using Clang
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	set(CMAKE_CXX_FLAGS " -Wextra ${CMAKE_CXX_FLAGS}")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Intel")
	# using Intel C++
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	# using Visual Studio C++
endif()
set(PROTOBUFS_DIR ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)
message(STATUS
		${CRYPTOPP_INCLUDE_DIR})
include_directories(
	${PROTOBUF_INCLUDE_DIRS}
	${CRYPTOPP_INCLUDE_DIR}
	${LibArchive_INCLUDE_DIRS}
	${CMAKE_CURRENT_BINARY_DIR}
)

include_directories($<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../certify/include>)
add_library(steam++
	steam++.cpp
	cmclient.cpp
	handlers.cpp
	${PROTO_SRCS}
	SteamCrypto.cpp)

target_link_libraries(steam++
	${PROTOBUF_LIBRARIES}
	${CRYPTOPP_LIBRARIES}
	${LibArchive_LIBRARIES}
)
IF (WIN32)
	add_compile_definitions(WIN32_LEAN_AND_MEAN)
	add_compile_definitions(BOOST_ASIO_NO_WIN32_LEAN_AND_MEAN )
ENDIF()