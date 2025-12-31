cmake_minimum_required(VERSION 3.10) 

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY 
    ${CMAKE_SOURCE_DIR}/outputs/
) 

project(Cdisasm VERSION 0.1.0 LANGUAGES C) 

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 平台相关编译选项
if(MSVC)
    # MSVC编译器选项
    add_compile_options(/W3 /O2)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    # GCC/Clang编译器选项
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O3")
endif()

# 头文件
set(HEADERS
    arm64_disasm.h
    arm64_decode_table.h
)

# 源文件
set(SOURCES
    arm64_disasm.c
    arm64_disasm_utils.c
    arm64_disasm_loadstore.c
    arm64_disasm_dataproc.c
    arm64_disasm_branch.c
    arm64_disasm_float.c
)

# 测试程序
add_executable(test_disasm 
    ${SOURCES}
    test_disasm.c
)

# 可选：构建静态库
add_library(arm64_disasm STATIC ${SOURCES})
target_include_directories(arm64_disasm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
