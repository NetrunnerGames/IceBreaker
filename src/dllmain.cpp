#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <string>

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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        LoadRealVersionDll();
        break;
    case DLL_PROCESS_DETACH:
        if (g_realVersionDll)
        {
            FreeLibrary(g_realVersionDll);
            g_realVersionDll = NULL;
        }
        break;
    }
    return TRUE;
}
