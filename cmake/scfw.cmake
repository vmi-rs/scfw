# Global options (can be overridden per-target via properties)
option(SCFW_OPT_DEBUG_INFO "Enable debug info in output binary (PDB/CodeView on Windows)" OFF)
option(SCFW_OPT_CLEANUP "Enable self-cleanup (free shellcode memory on exit)" OFF)
option(SCFW_OPT_ZERO_BASE "Set PE image base to 0 on x86" OFF)
option(SCFW_OPT_LTO "Enable Link-Time Optimization" ON)
set(SCFW_LTO_LEVEL 2 CACHE STRING "LTO optimization level, 0-3 (default=2)")
set(SCFW_FILE_ALIGNMENT 1 CACHE STRING "PE file alignment in bytes (default=1)")
set(SCFW_FUNCTION_ALIGNMENT 1 CACHE STRING "Function alignment in bytes (default=1)")

# Target is set by toolchain file via CMAKE_CXX_COMPILER_TARGET
if(NOT CMAKE_CXX_COMPILER_TARGET)
    message(FATAL_ERROR "CMAKE_CXX_COMPILER_TARGET not set. Use a toolchain file.")
endif()

# Force .exe extension for Windows PE output.
# Both forms are needed: the normal variable overrides the empty value set by
# CMake's Generic platform module in the current scope, and the cache variable
# ensures it applies in the consumer's scope when scfw is a subdirectory.
set(CMAKE_EXECUTABLE_SUFFIX ".exe" CACHE STRING "" FORCE)
set(CMAKE_EXECUTABLE_SUFFIX ".exe")

# Set default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Load shared cmake modules
include(${CMAKE_CURRENT_LIST_DIR}/llvm_paths.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/winsdk.cmake)

message(STATUS "Target: ${CMAKE_CXX_COMPILER_TARGET}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Base compiler flags for position-independent, stdlib-free shellcode
set(SCFW_COMPILE_FLAGS
    -D_HAS_EXCEPTIONS=0
    -D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
    -fno-exceptions
    -fno-rtti
    -fno-stack-protector
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -fdata-sections
    -ffunction-sections
    -fno-builtin
    -ffreestanding
    -fno-threadsafe-statics
    -gcodeview
    -mno-stack-arg-probe           # Disable __chkstk emission
    --target=${CMAKE_CXX_COMPILER_TARGET}

    ${SCFW_WINSDK_COMPILE_OPTIONS}

    # scfw provides implementations for SDK-declared functions
    -Wno-inconsistent-dllimport
)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "X86")
    list(APPEND SCFW_COMPILE_FLAGS
        -mno-sse
        -Xclang -fdefault-calling-conv=fastcall
    )
endif()

# Build-type specific optimization flags.
# -Os is the smallest choice for nearly every payload. -Oz occasionally wins,
# but the decision is per payload, so it belongs in the payload's own
# CMakeLists (see README, "Build Options") rather than in a global option.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    list(APPEND SCFW_COMPILE_FLAGS -O0)
else()
    list(APPEND SCFW_COMPILE_FLAGS
        -Os
        -fmerge-all-constants      # Merge identical string literals and constants
    )
endif()

# Function alignment override
if(SCFW_FUNCTION_ALIGNMENT GREATER 0)
    list(APPEND SCFW_COMPILE_FLAGS -falign-functions=${SCFW_FUNCTION_ALIGNMENT})
endif()

# Linker flags
set(SCFW_LINK_FLAGS
    --target=${CMAKE_CXX_COMPILER_TARGET}
    -nostdlib
    -nostartfiles
    -fuse-ld=lld
    -Wl,/OPT:REF                   # Remove unreferenced code/data
    -Wl,/OPT:ICF                   # Merge identical COMDAT sections (string pooling)
)

# Require lld for linking
find_program(LLD_EXECUTABLE lld-link
    HINTS ${SCFW_LLVM_SEARCH_PATHS}
    REQUIRED
)
message(STATUS "Found lld: ${LLD_EXECUTABLE}")

# Find llvm-objcopy for shellcode extraction
find_program(LLVM_OBJCOPY llvm-objcopy
    HINTS ${SCFW_LLVM_SEARCH_PATHS}
    REQUIRED
)
message(STATUS "Found llvm-objcopy: ${LLVM_OBJCOPY}")

# Find llvm-readobj for PE verification
find_program(LLVM_READOBJ llvm-readobj
    HINTS ${SCFW_LLVM_SEARCH_PATHS}
    REQUIRED
)
message(STATUS "Found llvm-readobj: ${LLVM_READOBJ}")

# Cache paths for use in verification script
set(SCFW_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE INTERNAL "scfw cmake directory")

# Define inherited properties (target -> directory -> global)
define_property(TARGET PROPERTY SCFW_OPT_DEBUG_INFO INHERITED
    BRIEF_DOCS "Enable debug info (PDB/CodeView)"
    FULL_DOCS  "Includes CodeView debug info in the output PE via /DEBUG."
               " Adds an .rdata section to the PE."
               " Useful for debugging with a disassembler."
               " Default: OFF.")
define_property(DIRECTORY PROPERTY SCFW_OPT_DEBUG_INFO INHERITED
    BRIEF_DOCS "Enable debug info (PDB/CodeView)"
    FULL_DOCS  "Includes CodeView debug info in the output PE via /DEBUG."
               " Adds an .rdata section to the PE."
               " Useful for debugging with a disassembler."
               " Default: OFF.")
set_property(GLOBAL PROPERTY SCFW_OPT_DEBUG_INFO ${SCFW_OPT_DEBUG_INFO})

define_property(TARGET PROPERTY SCFW_OPT_CLEANUP INHERITED
    BRIEF_DOCS "Enable self-cleanup"
    FULL_DOCS  "The shellcode frees its own memory on exit via VirtualFree"
               " (user-mode) or ExFreePool (kernel-mode)."
               " Maps to SCFW_ENABLE_CLEANUP and controls whether the"
               " assembly startup wrapper (start.S) is linked in."
               " Default: OFF.")
define_property(DIRECTORY PROPERTY SCFW_OPT_CLEANUP INHERITED
    BRIEF_DOCS "Enable self-cleanup"
    FULL_DOCS  "The shellcode frees its own memory on exit via VirtualFree"
               " (user-mode) or ExFreePool (kernel-mode)."
               " Maps to SCFW_ENABLE_CLEANUP and controls whether the"
               " assembly startup wrapper (start.S) is linked in."
               " Default: OFF.")
set_property(GLOBAL PROPERTY SCFW_OPT_CLEANUP ${SCFW_OPT_CLEANUP})

define_property(TARGET PROPERTY SCFW_OPT_LTO INHERITED
    BRIEF_DOCS "Enable Link-Time Optimization"
    FULL_DOCS  "Generally reduces shellcode size by eliminating dead code"
               " across translation units. Can sometimes increase size."
               " Default: ON.")
define_property(DIRECTORY PROPERTY SCFW_OPT_LTO INHERITED
    BRIEF_DOCS "Enable Link-Time Optimization"
    FULL_DOCS  "Generally reduces shellcode size by eliminating dead code"
               " across translation units. Can sometimes increase size."
               " Default: ON.")
set_property(GLOBAL PROPERTY SCFW_OPT_LTO ${SCFW_OPT_LTO})

define_property(TARGET PROPERTY SCFW_LTO_LEVEL INHERITED
    BRIEF_DOCS "LTO optimization level"
    FULL_DOCS  "Optimization level of the LTO pipeline that runs in the"
               " linker (/OPT:LLDLTO), where the final code for an LTO build"
               " is generated. Only has an effect when SCFW_OPT_LTO is ON."
               " Lower levels inline less, which often shrinks the shellcode."
               " Default: 2, the lld default.")
define_property(DIRECTORY PROPERTY SCFW_LTO_LEVEL INHERITED
    BRIEF_DOCS "LTO optimization level"
    FULL_DOCS  "Optimization level of the LTO pipeline that runs in the"
               " linker (/OPT:LLDLTO), where the final code for an LTO build"
               " is generated. Only has an effect when SCFW_OPT_LTO is ON."
               " Lower levels inline less, which often shrinks the shellcode."
               " Default: 2, the lld default.")
set_property(GLOBAL PROPERTY SCFW_LTO_LEVEL ${SCFW_LTO_LEVEL})

define_property(TARGET PROPERTY SCFW_FILE_ALIGNMENT INHERITED
    BRIEF_DOCS "PE file alignment in bytes"
    FULL_DOCS  "The default of 1 produces the smallest PE, but it is technically"
               " invalid - Windows loaders and IDA Pro may reject it."
               " The shellcode itself works fine."
               " Set to 0 to use the linker default, producing a valid PE"
               " executable at the cost of some padding."
               " Default: 1.")
define_property(DIRECTORY PROPERTY SCFW_FILE_ALIGNMENT INHERITED
    BRIEF_DOCS "PE file alignment in bytes"
    FULL_DOCS  "The default of 1 produces the smallest PE, but it is technically"
               " invalid - Windows loaders and IDA Pro may reject it."
               " The shellcode itself works fine."
               " Set to 0 to use the linker default, producing a valid PE"
               " executable at the cost of some padding."
               " Default: 1.")
set_property(GLOBAL PROPERTY SCFW_FILE_ALIGNMENT ${SCFW_FILE_ALIGNMENT})

define_property(TARGET PROPERTY SCFW_FUNCTION_ALIGNMENT INHERITED
    BRIEF_DOCS "Function alignment in bytes"
    FULL_DOCS  "Controls padding between functions."
               " Default of 1 means no padding, producing the smallest binary."
               " Set to 0 to use the linker default."
               " Affects both C++ code (-falign-functions=N) and assembly (.p2align)."
               " Default: 1.")
define_property(DIRECTORY PROPERTY SCFW_FUNCTION_ALIGNMENT INHERITED
    BRIEF_DOCS "Function alignment in bytes"
    FULL_DOCS  "Controls padding between functions."
               " Default of 1 means no padding, producing the smallest binary."
               " Set to 0 to use the linker default."
               " Affects both C++ code (-falign-functions=N) and assembly (.p2align)."
               " Default: 1.")
set_property(GLOBAL PROPERTY SCFW_FUNCTION_ALIGNMENT ${SCFW_FUNCTION_ALIGNMENT})

# Function to extract .text section to .bin file after building.
function(scfw_extract_shellcode target_name)
    # Apply LTO if enabled
    get_property(_lto TARGET ${target_name} PROPERTY SCFW_OPT_LTO)
    if(_lto)
        get_property(_lto_level TARGET ${target_name} PROPERTY SCFW_LTO_LEVEL)
        target_compile_options(${target_name} PRIVATE -flto)
        target_link_options(${target_name} PRIVATE
            -flto
            -Wl,/OPT:LLDLTO=${_lto_level}
        )
        message(STATUS "LTO enabled for ${target_name} (level ${_lto_level})")
    endif()

    # Apply debug info if enabled
    get_property(_debug_info TARGET ${target_name} PROPERTY SCFW_OPT_DEBUG_INFO)
    if(_debug_info)
        target_link_options(${target_name} PRIVATE -Wl,/DEBUG)
        message(STATUS "Debug info enabled for ${target_name}")
    endif()

    # Apply file alignment if set
    get_property(_file_align TARGET ${target_name} PROPERTY SCFW_FILE_ALIGNMENT)
    if(_file_align GREATER 0)
        target_link_options(${target_name} PRIVATE -Wl,/FILEALIGN:${_file_align})
        message(STATUS "File alignment set to ${_file_align} for ${target_name}")
    endif()

    # Extract shellcode only for non-Debug builds
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(_bin_file "$<TARGET_FILE_DIR:${target_name}>/${target_name}.bin")

        add_custom_command(TARGET ${target_name} POST_BUILD
            # Reject anything that is not a self-contained single-section
            # image (the shellcode only carries .text).
            COMMAND ${CMAKE_COMMAND}
                -DLLVM_READOBJ=${LLVM_READOBJ}
                -DPE_FILE=$<TARGET_FILE:${target_name}>
                -P ${SCFW_CMAKE_DIR}/post-build/verify_pe.cmake

            # Dump .text as a flat blob.
            COMMAND ${LLVM_OBJCOPY}
                --dump-section=.text=${_bin_file}
                $<TARGET_FILE:${target_name}>

            # The dump stops at SizeOfRawData, so pad the blob up to
            # VirtualSize, which includes the uninitialized data at the end.
            COMMAND ${CMAKE_COMMAND}
                -DLLVM_READOBJ=${LLVM_READOBJ}
                -DLLVM_OBJCOPY=${LLVM_OBJCOPY}
                -DPE_FILE=$<TARGET_FILE:${target_name}>
                -DBIN_FILE=${_bin_file}
                -P ${SCFW_CMAKE_DIR}/post-build/pad_bin.cmake

            # Report the final size.
            COMMAND ${CMAKE_COMMAND}
                -DBIN_FILE=${_bin_file}
                -P ${SCFW_CMAKE_DIR}/post-build/print_size.cmake
            COMMENT "Verifying and extracting shellcode: ${target_name}.bin"
            VERBATIM
        )
    else()
        message(STATUS "Shellcode extraction disabled for Debug build: ${target_name}")
    endif()
endfunction()
