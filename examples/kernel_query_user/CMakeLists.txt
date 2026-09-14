add_executable(kernel_query_user main.cpp)
target_link_libraries(kernel_query_user PRIVATE scfw)

# The default LTO level inlines this payload's call graph into one huge
# function, which more than doubles it. Level 1 inlines less.
set_target_properties(kernel_query_user PROPERTIES SCFW_LTO_LEVEL 1)

scfw_extract_shellcode(kernel_query_user)
