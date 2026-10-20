#include "VersionProxy.h"
#include <string>

namespace IceBreaker {

HMODULE VersionProxy::g_realVersionDll = NULL;

void VersionProxy::LoadRealDll() {
    if (g_realVersionDll) return;
    wchar_t sysDir[MAX_PATH];
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) return;
    std::wstring realPath = std::wstring(sysDir) + L"\\version.dll";
    // LoadLibraryW on an absolute system path can never recurse into our proxy.
    g_realVersionDll = LoadLibraryW(realPath.c_str());
}

void VersionProxy::UnloadRealDll() {
    if (g_realVersionDll) {
        FreeLibrary(g_realVersionDll);
        g_realVersionDll = NULL;
    }
}

void* VersionProxy::Original(const char* name) {
    if (!g_realVersionDll) return nullptr;
    return reinterpret_cast<void*>(GetProcAddress(g_realVersionDll, name));
}

} // namespace IceBreaker
