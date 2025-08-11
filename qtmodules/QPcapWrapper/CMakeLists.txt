cmake_minimum_required(VERSION 3.16)

project(QPcapWrapper LANGUAGES CXX)

# 包含头文件目录
set(PCAP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Include)
include_directories(${PCAP_INCLUDE_DIR})

# 链接平台相关的 pcap 库
if(WIN32)
    # 假设静态库/动态库都在 Lib/ 下按架构放
    if(CMAKE_SIZEOF_VOID_P EQUAL 8) # x64
        set(PCAP_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Lib/x64)
    else()
        set(PCAP_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Lib/ARM64)
    endif()
    link_directories(${PCAP_LIB_DIR})
endif()

# 源文件
file(GLOB_RECURSE WRAPPER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/Src/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Src/*.h
)

# 编译为静态库
add_library(QPcapWrapper STATIC ${WRAPPER_SOURCES})

# 链接第三方依赖
target_link_libraries(QPcapWrapper PRIVATE Qt5::Core Qt5::Network wpcap Packet)

# 公开头文件路径
target_include_directories(QPcapWrapper PUBLIC ${PCAP_INCLUDE_DIR})
