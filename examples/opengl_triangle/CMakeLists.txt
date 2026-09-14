add_executable(opengl_triangle main.cpp)
target_link_libraries(opengl_triangle PRIVATE scfw)

# LTO inlining more than doubles this payload at the default level. Level 1
# ties with LTO off, so there is nothing left for LTO to win here.
set_target_properties(opengl_triangle PROPERTIES SCFW_OPT_LTO OFF)

scfw_extract_shellcode(opengl_triangle)
