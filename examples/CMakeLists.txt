# CMakeLists.txt for examples

# Add the basic encryption example
add_executable(basic_encryption_example basic_encryption_example.cpp)

target_link_libraries(basic_encryption_example
    PRIVATE
        obscuraproto
        sodium
)

