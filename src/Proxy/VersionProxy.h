#pragma once
#include <windows.h>

namespace IceBreaker {

/// <summary>
/// Clean system version.dll forwarder. IceBreaker exports the six exported
/// version.dll entry points and forwards them to the real system copy loaded
/// from %SystemRoot%\System32. The export forwarders themselves live in
/// version.def (src/version.def); this module owns the underlying handles.
/// </summary>
class VersionProxy {
public:
    static void LoadRealDll();
    static void UnloadRealDll();

    // Resolved originals (null until LoadRealDll succeeds)
    static HMODULE RealModule() { return g_realVersionDll; }
    static void* Original(const char* name);

private:
    static HMODULE g_realVersionDll;
};

} // namespace IceBreaker
