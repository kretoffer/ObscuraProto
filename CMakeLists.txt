cmake_minimum_required(VERSION 3.11)

# Project name and version
project(ObscuraProto VERSION 1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set a minimum policy version to allow older CMake scripts from dependencies to run.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# ##############################################################################
# # Cryptography Library (libsodium)
# ##############################################################################
include(FetchContent)

# Declare libsodium dependency.
# For production, it is highly recommended to pin this to a specific GIT_TAG
# or commit hash.
FetchContent_Declare(
    libsodium
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG        1.0.18 # Using a stable tag
)

# Make libsodium available to the project
FetchContent_MakeAvailable(libsodium)

# Declare asio dependency (for websocketpp)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-28-0 # Using a stable tag
)
FetchContent_MakeAvailable(asio)

# Declare websocketpp dependency
FetchContent_Declare(
    websocketpp
    GIT_REPOSITORY https://github.com/zaphoyd/websocketpp.git
    GIT_TAG 0.8.2 # Using a stable tag
)
FetchContent_MakeAvailable(websocketpp)



# ##############################################################################
# # Library Target
# ##############################################################################

# Add the library target
add_library(obscuraproto)

# Add source files to the library
target_sources(obscuraproto
    PRIVATE
        src/packet.cpp
        src/crypto.cpp
        src/session.cpp
        src/handshake_messages.cpp
        src/ws_client.cpp
        src/ws_server.cpp
)

# Public include directories
target_include_directories(obscuraproto
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${asio_SOURCE_DIR}/asio/include
        ${websocketpp_SOURCE_DIR}
)

# Add compile definitions
target_compile_definitions(obscuraproto
    PUBLIC
        ASIO_STANDALONE
)

# Link external libraries
find_package(Threads REQUIRED)
target_link_libraries(obscuraproto
    PUBLIC
        sodium
        Threads::Threads
)


# ##############################################################################
# # Tests (optional, using GoogleTest)
# ##############################################################################
#
# enable_testing()
#
# # Add tests subdirectory
# add_subdirectory(tests)


# ##############################################################################
# # Examples (optional)
# ##############################################################################

# Add examples subdirectory
add_subdirectory(examples)
