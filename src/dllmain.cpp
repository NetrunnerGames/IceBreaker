#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <thread>
#include "Core/HookManager.h"
#include "Core/PatchEngine.h"
#include "Steam/Interfaces.h"
#include "Steam/LuaLoader.h"
#include "Proxy/VersionProxy.h"

// Export forwarders for system version.dll (see version.def).
typedef BOOL(WINAPI* pfnGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI* pfnGetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD(WINAPI* pfnGetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef DWORD(WINAPI* pfnGetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef BOOL(WINAPI* pfnVerQueryValueA)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL(WINAPI* pfnVerQueryValueW)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

extern "C" {

BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR filename, DWORD handle, DWORD len, LPVOID data)
{
    auto fn = reinterpret_cast<pfnGetFileVersionInfoA>(IceBreaker::VersionProxy::Original("GetFileVersionInfoA"));
    return fn ? fn(filename, handle, len, data) : FALSE;
}

BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR filename, DWORD handle, DWORD len, LPVOID data)
{
    auto fn = reinterpret_cast<pfnGetFileVersionInfoW>(IceBreaker::VersionProxy::Original("GetFileVersionInfoW"));
    return fn ? fn(filename, handle, len, data) : FALSE;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR filename, LPDWORD handle)
{
    auto fn = reinterpret_cast<pfnGetFileVersionInfoSizeA>(IceBreaker::VersionProxy::Original("GetFileVersionInfoSizeA"));
    return fn ? fn(filename, handle) : 0;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR filename, LPDWORD handle)
{
    auto fn = reinterpret_cast<pfnGetFileVersionInfoSizeW>(IceBreaker::VersionProxy::Original("GetFileVersionInfoSizeW"));
    return fn ? fn(filename, handle) : 0;
}

BOOL WINAPI Proxy_VerQueryValueA(LPCVOID block, LPCSTR subblock, LPVOID* buffer, PUINT len)
{
    auto fn = reinterpret_cast<pfnVerQueryValueA>(IceBreaker::VersionProxy::Original("VerQueryValueA"));
    return fn ? fn(block, subblock, buffer, len) : FALSE;
}

BOOL WINAPI Proxy_VerQueryValueW(LPCVOID block, LPCWSTR subblock, LPVOID* buffer, PUINT len)
{
    auto fn = reinterpret_cast<pfnVerQueryValueW>(IceBreaker::VersionProxy::Original("VerQueryValueW"));
    return fn ? fn(block, subblock, buffer, len) : FALSE;
}

}

static void InitializeIceBreaker()
{
    IceBreaker::HookManager::Log("IceBreaker initializing...");
    IceBreaker::HookManager::Initialize();

    // Load manifests from config/stplug-in (parsed before any hook fires so the
    // unlock set is populated by the time Steam's UI begins requesting ownership).
    IceBreaker::LuaLoader::LoadPluginManifests();

    // Hot-reload: re-parse manifests whenever a .lua under config/stplug-in changes.
    IceBreaker::LuaLoader::StartReloadWatcher();

    // Hook CreateInterface and SteamInternal_CreateInterface in steamclient64.dll
    // (SmokeAPI-style dynamic interface interception).
    IceBreaker::Interfaces::HookFactories();

    // Wait for steamui.dll to load if not already loaded, then apply the embedded
    // AOB patterns (OST-style in-memory patching).
    std::thread([]() {
        int attempts = 0;
        while (!GetModuleHandleW(L"steamui.dll") && attempts < 150) {
            Sleep(200);
            attempts++;
        }
        Sleep(500); // Give the loader a brief window to finish imports/relocations
        IceBreaker::PatchEngine::ApplyInMemoryPatches();
    }).detach();

    IceBreaker::HookManager::Log("IceBreaker initialization complete.");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        IceBreaker::VersionProxy::LoadRealDll();
        std::thread(InitializeIceBreaker).detach();
        break;
    case DLL_PROCESS_DETACH:
        IceBreaker::LuaLoader::StopReloadWatcher();
        IceBreaker::HookManager::Shutdown();
        IceBreaker::VersionProxy::UnloadRealDll();
        break;
    }
    return TRUE;
}
