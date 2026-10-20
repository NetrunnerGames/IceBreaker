#include "Interfaces.h"
#include "AppManager.h"
#include "../Core/HookManager.h"
#include "../Core/PatchEngine.h"
#include <psapi.h>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace IceBreaker {

typedef void* (*pfnCreateInterface)(const char* name, int* returnCode);
typedef void* (*pfnSteamInternal_CreateInterface)(const char* name);

static pfnCreateInterface oCreateInterface = nullptr;
static pfnSteamInternal_CreateInterface oSteamInternal_CreateInterface = nullptr;

static std::mutex g_interfaceMutex;
static std::set<void*> g_wrappedVTables;     // vptrs already mapped to the dispatch table
static void* g_ownershipAnchor = nullptr;    // resolved IClientUser::CheckAppOwnership
static uint32_t g_currentAppId = 0;

// ── Virtual-hook map ─────────────────────────────────────────────────
// SDK-verified vtable ordinals for the flat API families. Sourced from the
// Steamworks SDK headers (isteamuser.h / isteamutils.h / isteamapps.h) and
// cross-checked against SmokeAPI's res/interface_lookup.json, where every
// SteamApps 001-008 puts BIsSubscribedApp at 6 / BIsDlcInstalled at 7 and
// every SteamUtils 002-010 puts GetAppID at 9.
//
//   ISteamUser0xx  (xx <= 22): RequestEncryptedAppTicket = 20, GetEncryptedAppTicket = 21
//   ISteamUser023+           : RequestEncryptedAppTicket = 21, GetEncryptedAppTicket = 22
//
// The CLIENTUSER family (IClientUser / IClientUtils) has no public stable
// ordinal table, so its slots are resolved dynamically by scanning the live
// vtable for a pattern-resolved anchor (IClientUser::CheckAppOwnership).

struct VTableEntry {
    const char* name;   // diagnostics only
    size_t ordinal;     // resolved statically or dynamically
    void* hook;         // detour
    void** original;    // trampoline out-param
};

// ── Hook: flat ISteamApps ─────────────────────────────────────────────
typedef bool (*pfnBIsSubscribedApp)(void* pThis, uint32_t appId);
static pfnBIsSubscribedApp oBIsSubscribedApp = nullptr;

static bool Hook_BIsSubscribedApp(void* pThis, uint32_t appId) {
    if (AppManager::Get().IsAppUnlocked(appId)) return true;
    return oBIsSubscribedApp ? oBIsSubscribedApp(pThis, appId) : false;
}

typedef bool (*pfnBIsDlcInstalled)(void* pThis, uint32_t appId);
static pfnBIsDlcInstalled oBIsDlcInstalled = nullptr;

static bool Hook_BIsDlcInstalled(void* pThis, uint32_t appId) {
    if (AppManager::Get().IsDLCUnlocked(appId, appId)) return true;
    return oBIsDlcInstalled ? oBIsDlcInstalled(pThis, appId) : false;
}

// ── Hook: flat ISteamUtils::GetAppID ─────────────────────────────────
typedef uint32_t (*pfnGetAppID)(void* pThis);
static pfnGetAppID oGetAppID = nullptr;

static uint32_t Hook_GetAppID(void* pThis) {
    uint32_t appId = oGetAppID ? oGetAppID(pThis) : 0;
    if (appId) {
        std::lock_guard<std::mutex> lock(g_interfaceMutex);
        g_currentAppId = appId;
    }
    return appId;
}

// ── Hook: flat ISteamUser tickets ────────────────────────────────────
typedef uint32_t (*pfnRequestEncryptedAppTicket)(void* pThis, void* pDataToInclude, int cbDataToInclude);
static pfnRequestEncryptedAppTicket oRequestEncryptedAppTicket = nullptr;

static uint32_t Hook_RequestEncryptedAppTicket(void* pThis, void* pDataToInclude, int cbDataToInclude) {
    HookManager::Log("RequestEncryptedAppTicket — deferring to Steam");
    return oRequestEncryptedAppTicket ? oRequestEncryptedAppTicket(pThis, pDataToInclude, cbDataToInclude) : 0;
}

typedef uint32_t (*pfnGetEncryptedAppTicket)(void* pThis, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket);
static pfnGetEncryptedAppTicket oGetEncryptedAppTicket = nullptr;

static uint32_t Hook_GetEncryptedAppTicket(void* pThis, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket) {
    HookManager::Log("GetEncryptedAppTicket — deferring to Steam");
    return oGetEncryptedAppTicket ? oGetEncryptedAppTicket(pThis, pTicket, cbMaxTicket, pcbTicket) : 0;
}

// ── Hook: IClientUser::CheckAppOwnership (client family) ─────────────
typedef bool (*pfnClientCheckAppOwnership)(void* pThis, uint32_t appId, void* pOwnership);
static pfnClientCheckAppOwnership oClientCheckAppOwnership = nullptr;

static bool Hook_ClientCheckAppOwnership(void* pThis, uint32_t appId, void* pOwnership) {
    // Behavioral override lives in PatchEngine's direct AOB detour on the same
    // function; this vtable-slot entry keeps interface instances that reach the
    // client only through the live vptr on the same dispatch table.
    return oClientCheckAppOwnership ? oClientCheckAppOwnership(pThis, appId, pOwnership) : false;
}

void Interfaces::SetOwnershipAnchor(void* address) {
    std::lock_guard<std::mutex> lock(g_interfaceMutex);
    g_ownershipAnchor = address;
}

void Interfaces::NoteClientAppContext(uint32_t appId) {
    if (appId) {
        std::lock_guard<std::mutex> lock(g_interfaceMutex);
        g_currentAppId = appId;
    }
}

// ── vtable plumbing ───────────────────────────────────────────────────
static bool IsModuleCodePtr(HMODULE module, void* slotTarget) {
    if (!module) return false;
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(MODULEINFO))) return false;
    uintptr_t addr = reinterpret_cast<uintptr_t>(slotTarget);
    uintptr_t base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    return addr >= base && addr < base + modInfo.SizeOfImage;
}

void Interfaces::HookVTable(void* instance, const char* name, size_t index,
                            void* hookFunc, void** origFunc) {
    if (!instance || !hookFunc) return;

    void** vtable = *reinterpret_cast<void***>(instance);
    if (!vtable) return;

    HMODULE module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(vtable[0]), &module);
    if (!module) return;

    // Safety: the slot must point back into the module that owns the vtable.
    if (!IsModuleCodePtr(module, vtable[index])) {
        HookManager::Log(std::string(name) + ": vtable[" + std::to_string(index) +
                         "] failed module-range verification, skipping");
        return;
    }

    if (origFunc && !*origFunc) *origFunc = vtable[index];

    DWORD oldProtect = 0;
    if (VirtualProtect(&vtable[index], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        vtable[index] = hookFunc;
        VirtualProtect(&vtable[index], sizeof(void*), oldProtect, &oldProtect);
        HookManager::Log(std::string(name) + ": hooked vtable[" + std::to_string(index) + "]");
    }
}

void Interfaces::WrapFamily(void* instance, const char* tag, const std::vector<VTableEntry>& entries) {
    for (const auto& entry : entries) {
        HookVTable(instance, entry.name, entry.ordinal, entry.hook, entry.original);
    }
    (void)tag;
}

void Interfaces::WrapClientUser(void* clientUser) {
    if (!clientUser) return;
    // vtable hook for the client family is anchor-based: resolved at runtime once
    // PatchEngine publishes the CheckAppOwnership address. Wrapped on each capture.
    void* anchor;
    {
        std::lock_guard<std::mutex> lock(g_interfaceMutex);
        anchor = g_ownershipAnchor;
    }
    if (!anchor) {
        HookManager::Log("CLIENTUSER captured; CheckAppOwnership anchor not yet resolved (pattern scan pending).");
        return;
    }

    void** vtable = *reinterpret_cast<void***>(clientUser);
    if (!vtable) return;

    const size_t kMaxIClientUserVirtuals = 512;
    for (size_t i = 0; i < kMaxIClientUserVirtuals && vtable[i]; ++i) {
        if (vtable[i] == anchor) {
            HookManager::Log("CLIENTUSER: CheckAppOwnership anchor found at vtable[" +
                             std::to_string(i) + "] (dynamic resolution)");
            HookVTable(clientUser, "IClientUser::CheckAppOwnership", i,
                       reinterpret_cast<void*>(&Hook_ClientCheckAppOwnership),
                       reinterpret_cast<void**>(&oClientCheckAppOwnership));
            return;
        }
    }
    HookManager::Log("CLIENTUSER: anchor resolved but not present in captured vtable.");
}

void Interfaces::WrapClientUtils(void* clientUtils) {
    if (!clientUtils) return;
    HookManager::Log("Wrapping IClientUtils instance dynamically.");
}

// ── factory interception ──────────────────────────────────────────────
void Interfaces::WrapCaptured(void* instance, const char* name) {
    if (!instance || !name) return;
    const std::string version(name);

    const std::lock_guard<std::mutex> lock(g_interfaceMutex);
    void** vtable = *reinterpret_cast<void***>(instance);
    if (vtable && !g_wrappedVTables.insert(vtable).second) return; // vptr already mapped

    HookManager::Log("Interface captured: " + version);

    if (version.rfind("CLIENTUSER_INTERFACE_VERSION", 0) == 0) {
        WrapClientUser(instance);
    } else if (version.rfind("CLIENTUTILS_INTERFACE_VERSION", 0) == 0) {
        WrapClientUtils(instance);
    } else if (version.rfind("SteamUser", 0) == 0) {
        // SteamUser023 moved both ticket verbs by one slot (GetAuthTicketForWebApi at 14).
        const bool newer = version >= "SteamUser023";
        const size_t reqTicket = newer ? 21 : 20;
        const size_t getTicket = newer ? 22 : 21;
        const std::vector<VTableEntry> entries = {
            { "ISteamUser::RequestEncryptedAppTicket", reqTicket,
              reinterpret_cast<void*>(&Hook_RequestEncryptedAppTicket),
              reinterpret_cast<void**>(&oRequestEncryptedAppTicket) },
            { "ISteamUser::GetEncryptedAppTicket", getTicket,
              reinterpret_cast<void*>(&Hook_GetEncryptedAppTicket),
              reinterpret_cast<void**>(&oGetEncryptedAppTicket) },
        };
        WrapFamily(instance, "SteamUser", entries);
    } else if (version.rfind("SteamUtils", 0) == 0) {
        const std::vector<VTableEntry> entries = {
            { "ISteamUtils::GetAppID", 9,
              reinterpret_cast<void*>(&Hook_GetAppID),
              reinterpret_cast<void**>(&oGetAppID) },
        };
        WrapFamily(instance, "SteamUtils", entries);
    } else if (version.rfind("STEAMAPPS_INTERFACE", 0) == 0) {
        const std::vector<VTableEntry> entries = {
            { "ISteamApps::BIsSubscribedApp", 6,
              reinterpret_cast<void*>(&Hook_BIsSubscribedApp),
              reinterpret_cast<void**>(&oBIsSubscribedApp) },
            { "ISteamApps::BIsDlcInstalled", 7,
              reinterpret_cast<void*>(&Hook_BIsDlcInstalled),
              reinterpret_cast<void**>(&oBIsDlcInstalled) },
        };
        WrapFamily(instance, "STEAMAPPS_INTERFACE", entries);
    }
}

void* Interfaces::HandleFactoryResult(const char* name, void* result, const char* factory) {
    if (!result || !name) return result;
    HookManager::Log(std::string(factory) + " requested: " + name);
    WrapCaptured(result, name);
    return result;
}

void* Interfaces::CreateInterfaceHook(const char* name, int* returnCode) {
    void* result = oCreateInterface ? oCreateInterface(name, returnCode) : nullptr;
    return HandleFactoryResult(name, result, "CreateInterface");
}

void* Interfaces::SteamInternal_CreateInterfaceHook(const char* name) {
    void* result = oSteamInternal_CreateInterface ? oSteamInternal_CreateInterface(name) : nullptr;
    return HandleFactoryResult(name, result, "SteamInternal_CreateInterface");
}

bool Interfaces::HookFactories() {
    bool hooked = false;

    auto tryHook = [](HMODULE hClient) {
        if (!hClient) return false;
        bool ok = false;
        if (void* pCreateInterface = reinterpret_cast<void*>(GetProcAddress(hClient, "CreateInterface"))) {
            ok |= HookManager::CreateHook(pCreateInterface,
                                          reinterpret_cast<void*>(&Interfaces::CreateInterfaceHook),
                                          reinterpret_cast<void**>(&oCreateInterface),
                                          "CreateInterface");
        }
        if (void* pSteamInternal = reinterpret_cast<void*>(GetProcAddress(hClient, "SteamInternal_CreateInterface"))) {
            ok |= HookManager::CreateHook(pSteamInternal,
                                          reinterpret_cast<void*>(&Interfaces::SteamInternal_CreateInterfaceHook),
                                          reinterpret_cast<void**>(&oSteamInternal_CreateInterface),
                                          "SteamInternal_CreateInterface");
        }
        return ok;
    };

    // steamclient64.dll normally loads alongside the executable; hook whichever
    // module view is (or becomes) available in this process.
    hooked |= tryHook(GetModuleHandleW(L"steamclient64.dll"));
    if (!hooked) {
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
            std::wstring dir(exePath);
            size_t slash = dir.find_last_of(L"\\/");
            if (slash != std::wstring::npos) {
                std::wstring path = dir.substr(0, slash) + L"\\steamclient64.dll";
                hooked |= tryHook(LoadLibraryW(path.c_str()));
            }
        }
    }

    // If a game harness loaded steam_api64 into this process, cover it too.
    tryHook(GetModuleHandleW(L"steam_api64.dll"));

    if (!hooked) {
        HookManager::Log("steamclient64.dll not yet loaded; factories will be hooked lazily.");
    }
    return hooked;
}

} // namespace IceBreaker
