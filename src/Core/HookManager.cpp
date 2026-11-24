#include "HookManager.h"
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace IceBreaker {

static std::mutex g_logMutex;

static std::string GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm bt{};
#if defined(_WIN32)
    localtime_s(&bt, &in_time_t);
#else
    localtime_r(&in_time_t, &bt);
#endif

    std::ostringstream ss;
    ss << std::put_time(&bt, "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

void HookManager::Log(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::ofstream out("icebreaker.log", std::ios::app);
    if (out.is_open()) {
        out << "[" << GetCurrentTimestamp() << "] [IceBreaker] " << message << "\n";
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
