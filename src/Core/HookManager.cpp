#include "HookManager.h"
#include <fstream>
#include <mutex>

namespace IceBreaker {

static std::mutex g_logMutex;

void HookManager::Log(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::ofstream out("icebreaker.log", std::ios::app);
    if (out.is_open()) {
        out << "[IceBreaker] " << message << "\n";
    }
}

bool HookManager::Initialize() {
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
        Log("Failed to initialize MinHook. Status: " + std::to_string(status));
        return false;
    }
    Log("MinHook initialized successfully.");
    return true;
}

void HookManager::Shutdown() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    Log("HookManager shutdown.");
}

bool HookManager::CreateHook(void* target, void* detour, void** original, const std::string& name) {
    if (!target || !detour) {
        Log("CreateHook invalid pointer for " + name);
        return false;
    }

    MH_STATUS status = MH_CreateHook(target, detour, original);
    if (status != MH_OK) {
        Log("MH_CreateHook failed for " + name + " (status: " + std::to_string(status) + ")");
        return false;
    }

    status = MH_EnableHook(target);
    if (status != MH_OK) {
        Log("MH_EnableHook failed for " + name + " (status: " + std::to_string(status) + ")");
        return false;
    }

    Log("Hook active: " + name);
    return true;
}

bool HookManager::EnableHook(void* target) {
    return MH_EnableHook(target) == MH_OK;
}

bool HookManager::DisableHook(void* target) {
    return MH_DisableHook(target) == MH_OK;
}

bool HookManager::RemoveHook(void* target) {
    return MH_RemoveHook(target) == MH_OK;
}

} // namespace IceBreaker
