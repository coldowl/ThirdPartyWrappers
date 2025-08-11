cmake_minimum_required(VERSION 3.16)
project(ThirdPartyWrappers LANGUAGES CXX)

# 默认构建模式
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Qt 依赖
find_package(Qt5 REQUIRED COMPONENTS Core Network) # 根据实际需要加 Widgets、Gui 等

# 公共包含目录
include_directories(${CMAKE_SOURCE_DIR}/cmake)

# 递归添加 qtmodules 下的所有模块
file(GLOB WRAPPER_DIRS "${CMAKE_SOURCE_DIR}/qtmodules/*")
foreach(wrapper_dir ${WRAPPER_DIRS})
    if(EXISTS "${wrapper_dir}/Src")
        add_subdirectory(${wrapper_dir})
    endif()
endforeach()
