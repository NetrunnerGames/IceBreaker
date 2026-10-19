#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <thread>
#include "Core/HookManager.h"
#include "Core/PatchEngine.h"
#include "Steam/Interfaces.h"
#include "Steam/LuaLoader.h"

#pragma comment(lib, "shlwapi.lib")

// Export forwarders for system version.dll
HMODULE g_realVersionDll = NULL;

typedef BOOL(WINAPI* pfnGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI* pfnGetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD(WINAPI* pfnGetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef DWORD(WINAPI* pfnGetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef BOOL(WINAPI* pfnVerQueryValueA)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL(WINAPI* pfnVerQueryValueW)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

static pfnGetFileVersionInfoA oGetFileVersionInfoA = NULL;
static pfnGetFileVersionInfoW oGetFileVersionInfoW = NULL;
static pfnGetFileVersionInfoSizeA oGetFileVersionInfoSizeA = NULL;
static pfnGetFileVersionInfoSizeW oGetFileVersionInfoSizeW = NULL;
static pfnVerQueryValueA oVerQueryValueA = NULL;
static pfnVerQueryValueW oVerQueryValueW = NULL;

static void LoadRealVersionDll()
{
    if (g_realVersionDll) return;
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    std::string realPath = std::string(sysDir) + "\\version.dll";
    g_realVersionDll = LoadLibraryA(realPath.c_str());
    if (g_realVersionDll)
    {
        oGetFileVersionInfoA = (pfnGetFileVersionInfoA)GetProcAddress(g_realVersionDll, "GetFileVersionInfoA");
        oGetFileVersionInfoW = (pfnGetFileVersionInfoW)GetProcAddress(g_realVersionDll, "GetFileVersionInfoW");
        oGetFileVersionInfoSizeA = (pfnGetFileVersionInfoSizeA)GetProcAddress(g_realVersionDll, "GetFileVersionInfoSizeA");
        oGetFileVersionInfoSizeW = (pfnGetFileVersionInfoSizeW)GetProcAddress(g_realVersionDll, "GetFileVersionInfoSizeW");
        oVerQueryValueA = (pfnVerQueryValueA)GetProcAddress(g_realVersionDll, "VerQueryValueA");
        oVerQueryValueW = (pfnVerQueryValueW)GetProcAddress(g_realVersionDll, "VerQueryValueW");
    }
}

extern "C" {

BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR filename, DWORD handle, DWORD len, LPVOID data)
{
    LoadRealVersionDll();
    return oGetFileVersionInfoA ? oGetFileVersionInfoA(filename, handle, len, data) : FALSE;
}

BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR filename, DWORD handle, DWORD len, LPVOID data)
{
    LoadRealVersionDll();
    return oGetFileVersionInfoW ? oGetFileVersionInfoW(filename, handle, len, data) : FALSE;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR filename, LPDWORD handle)
{
    LoadRealVersionDll();
    return oGetFileVersionInfoSizeA ? oGetFileVersionInfoSizeA(filename, handle) : 0;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR filename, LPDWORD handle)
{
    LoadRealVersionDll();
    return oGetFileVersionInfoSizeW ? oGetFileVersionInfoSizeW(filename, handle) : 0;
}

BOOL WINAPI Proxy_VerQueryValueA(LPCVOID block, LPCSTR subblock, LPVOID* buffer, PUINT len)
{
    LoadRealVersionDll();
    return oVerQueryValueA ? oVerQueryValueA(block, subblock, buffer, len) : FALSE;
}

BOOL WINAPI Proxy_VerQueryValueW(LPCVOID block, LPCWSTR subblock, LPVOID* buffer, PUINT len)
{
    LoadRealVersionDll();
    return oVerQueryValueW ? oVerQueryValueW(block, subblock, buffer, len) : FALSE;
}

}

static void InitializeIceBreaker()
{
    IceBreaker::HookManager::Log("IceBreaker initializing...");
    IceBreaker::HookManager::Initialize();

    // Load manifests from config/stplug-in
    IceBreaker::LuaLoader::LoadPluginManifests();

    // Hook CreateInterface and SteamInternal_CreateInterface
    IceBreaker::Interfaces::HookFactories();

    // Wait for steamui.dll to load if not already loaded, then apply in-memory patterns
    std::thread([]() {
        int attempts = 0;
        while (!GetModuleHandleW(L"steamui.dll") && attempts < 50) {
            Sleep(200);
            attempts++;
        }
        Sleep(500); // Give loader a brief window to complete imports
        IceBreaker::PatchEngine::ApplyInMemoryPatches();
    }).detach();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        LoadRealVersionDll();
        std::thread(InitializeIceBreaker).detach();
        break;
    case DLL_PROCESS_DETACH:
        IceBreaker::HookManager::Shutdown();
        if (g_realVersionDll)
        {
            FreeLibrary(g_realVersionDll);
            g_realVersionDll = NULL;
        }
        break;
    }
    return TRUE;
}
