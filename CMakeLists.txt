cmake_minimum_required(VERSION 3.11)

# Project name and version
project(ObscuraProto VERSION 1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
)

# Public include directories
target_include_directories(obscuraproto
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

# Link external libraries
target_link_libraries(obscuraproto
    PUBLIC
        sodium
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
