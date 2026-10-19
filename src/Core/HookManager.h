#pragma once
#include <windows.h>
#include <unordered_map>
#include <string>
#include "MinHook.h"

namespace IceBreaker {

class HookManager {
public:
    static bool Initialize();
    static void Shutdown();

    static bool CreateHook(void* target, void* detour, void** original, const std::string& name = "");
    static bool EnableHook(void* target);
    static bool DisableHook(void* target);
    static bool RemoveHook(void* target);

    static void Log(const std::string& message);
};

} // namespace IceBreaker
