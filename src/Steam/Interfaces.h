#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

namespace IceBreaker {

class Interfaces {
public:
    // Hooks export factories in steamclient64.dll and steam_api64.dll
    static bool HookFactories();

    // Factory hook callbacks
    static void* CreateInterfaceHook(const char* name, int* returnCode);
    static void* SteamInternal_CreateInterfaceHook(const char* name);

private:
    static void HookVTable(void* instance, size_t index, void* hookFunc, void** origFunc);
    static void WrapClientUser(void* clientUser);
    static void WrapClientUtils(void* clientUtils);
};

} // namespace IceBreaker
