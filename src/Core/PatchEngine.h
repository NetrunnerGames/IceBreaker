#pragma once
#include <windows.h>
#include <string>
#include <unordered_map>
#include <cstdint>

namespace IceBreaker {

/// <summary>
/// Resolves the embedded AOB patterns on DLL attach and applies safe, non-destructive hooks.
/// </summary>
class PatchEngine {
public:
    static void ApplyInMemoryPatches();

    /// Returns the address resolved for a named pattern this session (0 if unresolved).
    static uintptr_t ResolvedAddress(const std::string& name);

    /// Publishes a freshly resolved pattern address into the session cache.
    static void CacheResolved(const std::string& name, uintptr_t addr);

    /// Address of the steamclient64.dll module hosting the client interfaces.
    static uintptr_t ClientBase();
    /// Address of the steamui.dll module hosting the library UI.
    static uintptr_t UIBase();

private:
    static std::unordered_map<std::string, uintptr_t> s_resolved;
};

} // namespace IceBreaker
