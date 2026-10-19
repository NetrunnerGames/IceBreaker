#include "Interfaces.h"
#include "AppManager.h"
#include "../Core/HookManager.h"
#include <unordered_map>
#include <mutex>

namespace IceBreaker {

typedef void* (*pfnCreateInterface)(const char* name, int* returnCode);
typedef void* (*pfnSteamInternal_CreateInterface)(const char* name);

static pfnCreateInterface oCreateInterface = nullptr;
static pfnSteamInternal_CreateInterface oSteamInternal_CreateInterface = nullptr;

static std::mutex g_interfaceMutex;
static std::unordered_map<void*, void**> g_origVTables;

void Interfaces::HookVTable(void* instance, size_t index, void* hookFunc, void** origFunc) {
    if (!instance || !hookFunc) return;

    void** vtable = *reinterpret_cast<void***>(instance);
    if (!vtable) return;

    if (origFunc && !*origFunc) {
        *origFunc = vtable[index];
    }

    DWORD oldProtect;
    if (VirtualProtect(&vtable[index], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        vtable[index] = hookFunc;
        VirtualProtect(&vtable[index], sizeof(void*), oldProtect, &oldProtect);
    }
}

// Hooked functions for IClientUser / SteamUser
typedef uint32_t (*pfnGetAppOwnershipTicketExtendedData)(void* pThis, uint32_t nAppID, void* pvBuffer, uint32_t cubBuffer, uint32_t* piAppId, uint32_t* piSteamId);
static pfnGetAppOwnershipTicketExtendedData oGetAppOwnershipTicketExtendedData = nullptr;

static uint32_t Hook_GetAppOwnershipTicketExtendedData(void* pThis, uint32_t nAppID, void* pvBuffer, uint32_t cubBuffer, uint32_t* piAppId, uint32_t* piSteamId) {
    if (AppManager::Get().IsAppUnlocked(nAppID)) {
        HookManager::Log("Bypassing AppOwnershipTicketExtendedData for unlocked AppID: " + std::to_string(nAppID));
        if (piAppId) *piAppId = nAppID;
        return 1; // Success
    }

    if (oGetAppOwnershipTicketExtendedData) {
        return oGetAppOwnershipTicketExtendedData(pThis, nAppID, pvBuffer, cubBuffer, piAppId, piSteamId);
    }
    return 0;
}

void Interfaces::WrapClientUser(void* clientUser) {
    if (!clientUser) return;
    HookManager::Log("Wrapping IClientUser instance dynamically.");
}

void Interfaces::WrapClientUtils(void* clientUtils) {
    if (!clientUtils) return;
    HookManager::Log("Wrapping IClientUtils instance dynamically.");
}

void* Interfaces::CreateInterfaceHook(const char* name, int* returnCode) {
    void* result = nullptr;
    if (oCreateInterface) {
        result = oCreateInterface(name, returnCode);
    }

    if (result && name) {
        std::string interfaceName(name);
        HookManager::Log("CreateInterface requested: " + interfaceName);
        if (interfaceName.find("CLIENTUSER_INTERFACE_VERSION") != std::string::npos ||
            interfaceName.find("SteamUser") != std::string::npos) {
            WrapClientUser(result);
        } else if (interfaceName.find("CLIENTUTILS_INTERFACE_VERSION") != std::string::npos ||
                   interfaceName.find("SteamUtils") != std::string::npos) {
            WrapClientUtils(result);
        }
    }
    return result;
}

void* Interfaces::SteamInternal_CreateInterfaceHook(const char* name) {
    void* result = nullptr;
    if (oSteamInternal_CreateInterface) {
        result = oSteamInternal_CreateInterface(name);
    }

    if (result && name) {
        std::string interfaceName(name);
        HookManager::Log("SteamInternal_CreateInterface requested: " + interfaceName);
        if (interfaceName.find("CLIENTUSER_INTERFACE_VERSION") != std::string::npos ||
            interfaceName.find("SteamUser") != std::string::npos) {
            WrapClientUser(result);
        } else if (interfaceName.find("CLIENTUTILS_INTERFACE_VERSION") != std::string::npos ||
                   interfaceName.find("SteamUtils") != std::string::npos) {
            WrapClientUtils(result);
        }
    }
    return result;
}

bool Interfaces::HookFactories() {
    HMODULE hClient = GetModuleHandleW(L"steamclient64.dll");
    if (!hClient) {
        hClient = LoadLibraryW(L"steamclient64.dll");
    }

    if (hClient) {
        void* pCreateInterface = reinterpret_cast<void*>(GetProcAddress(hClient, "CreateInterface"));
        if (pCreateInterface) {
            HookManager::CreateHook(pCreateInterface, &Interfaces::CreateInterfaceHook, 
                                   reinterpret_cast<void**>(&oCreateInterface), "steamclient64:CreateInterface");
        }

        void* pSteamInternal = reinterpret_cast<void*>(GetProcAddress(hClient, "SteamInternal_CreateInterface"));
        if (pSteamInternal) {
            HookManager::CreateHook(pSteamInternal, &Interfaces::SteamInternal_CreateInterfaceHook, 
                                   reinterpret_cast<void**>(&oSteamInternal_CreateInterface), "steamclient64:SteamInternal_CreateInterface");
        }
    }

    return true;
}

} // namespace IceBreaker
