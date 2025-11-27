# CMakeLists.txt for examples

# Add the basic encryption example
add_executable(basic_encryption_example basic_encryption_example.cpp)

target_link_libraries(basic_encryption_example
    PRIVATE
        obscuraproto
)

# Add the websocket example
add_executable(websocket_example websocket_example.cpp)

target_link_libraries(websocket_example
    PRIVATE
        obscuraproto
)

# Add the request-response example
add_executable(request_response_example request_response_example.cpp)

target_link_libraries(request_response_example
    PRIVATE
        obscuraproto
)

# Add the opcode_callbacks example
add_executable(opcode_callbacks_example opcode_callbacks_example.cpp)

target_link_libraries(opcode_callbacks_example
    PRIVATE
        obscuraproto
)
