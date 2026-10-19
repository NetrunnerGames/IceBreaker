#include "PatchEngine.h"
#include "Scanner.h"
#include "Patterns.h"
#include "HookManager.h"
#include "../Steam/AppManager.h"

namespace IceBreaker {

// Detour for ShouldShowAppInLibrary
typedef bool (*pfnShouldShowAppInLibrary)(void* pThis, uint32_t appId);
static pfnShouldShowAppInLibrary oShouldShowAppInLibrary = nullptr;

static bool Hook_ShouldShowAppInLibrary(void* pThis, uint32_t appId) {
    if (AppManager::Get().IsAppUnlocked(appId)) {
        return true;
    }
    if (oShouldShowAppInLibrary) {
        return oShouldShowAppInLibrary(pThis, appId);
    }
    return true;
}

// Detour for CheckAppOwnership
typedef bool (*pfnCheckAppOwnership)(void* pThis, uint32_t appId);
static pfnCheckAppOwnership oCheckAppOwnership = nullptr;

static bool Hook_CheckAppOwnership(void* pThis, uint32_t appId) {
    if (AppManager::Get().IsAppUnlocked(appId)) {
        return true;
    }
    if (oCheckAppOwnership) {
        return oCheckAppOwnership(pThis, appId);
    }
    return true;
}

void PatchEngine::ApplyInMemoryPatches() {
    HookManager::Log("Scanning in-memory patterns for SteamUI...");
    for (const auto& pat : g_SteamUIPatterns) {
        uintptr_t addr = Scanner::FindPattern(L"steamui.dll", pat.pattern);
        if (addr) {
            HookManager::Log("Found pattern " + std::string(pat.name) + " at 0x" + std::to_string(addr));
            if (std::string(pat.name) == "ShouldShowAppInLibrary") {
                HookManager::CreateHook(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(&Hook_ShouldShowAppInLibrary),
                                       reinterpret_cast<void**>(&oShouldShowAppInLibrary), pat.name);
            }
        } else {
            HookManager::Log("Pattern not found: " + std::string(pat.name));
        }
    }

    HookManager::Log("Scanning in-memory patterns for SteamClient...");
    for (const auto& pat : g_SteamClientPatterns) {
        uintptr_t addr = Scanner::FindPattern(L"steamclient64.dll", pat.pattern);
        if (addr) {
            HookManager::Log("Found pattern " + std::string(pat.name) + " at 0x" + std::to_string(addr));
            if (std::string(pat.name) == "CheckAppOwnership") {
                HookManager::CreateHook(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(&Hook_CheckAppOwnership),
                                       reinterpret_cast<void**>(&oCheckAppOwnership), pat.name);
            }
        } else {
            HookManager::Log("Pattern not found: " + std::string(pat.name));
        }
    }
}

} // namespace IceBreaker
