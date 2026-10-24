cmake_minimum_required(VERSION 3.15)
project(IceBreaker LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MinHook sources
set(MINHOOK_SOURCES
    vendor/minhook/src/buffer.c
    vendor/minhook/src/hook.c
    vendor/minhook/src/trampoline.c
    vendor/minhook/src/hde/hde32.c
    vendor/minhook/src/hde/hde64.c
)

# IceBreaker core sources
set(ICEBREAKER_SOURCES
    src/dllmain.cpp
    src/version.def
    src/Core/Scanner.cpp
    src/Core/HookManager.cpp
    src/Core/PatchEngine.cpp
    src/Proxy/VersionProxy.cpp
    src/Steam/AppManager.cpp
    src/Steam/LuaLoader.cpp
    src/Steam/Interfaces.cpp
    src/IPC/IpcServer.cpp
)

add_library(version SHARED
    ${MINHOOK_SOURCES}
    ${ICEBREAKER_SOURCES}
)

target_include_directories(version PRIVATE
    src
    vendor/minhook/include
)

target_link_libraries(version PRIVATE
    shlwapi
    psapi
    wininet
)
