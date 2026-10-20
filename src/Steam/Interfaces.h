#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace IceBreaker {

struct VTableEntry;

/// <summary>
/// SmokeAPI-style dynamic interface interception.
///
/// Hooks the exported factories of steamclient64.dll (CreateInterface and
/// SteamInternal_CreateInterface). Every interface instance Steam or an
/// in-process plugin requests is inspected: the live virtual method table
/// pointer (vptr) is captured and mapped into a hook dispatch table whose
/// vtable slots are resolved at runtime — either from SDK-verified per-version
/// ordinals (flat SteamUser/SteamUtils/SteamApps families) or by locating a
/// pattern-resolved anchor function inside the live vtable (CLIENTUSER family).
/// Nothing here depends on a hardcoded vtable RVA, so the mapping survives
/// Steam client updates as long as the interface version strings persist.
/// </summary>
class Interfaces {
public:
    // Hooks the export factories in steamclient64.dll (and steam_api64.dll if loaded)
    static bool HookFactories();

    // Factory hook callbacks
    static void* CreateInterfaceHook(const char* name, int* returnCode);
    static void* SteamInternal_CreateInterfaceHook(const char* name);

    // Called by PatchEngine once the IClientUser::CheckAppOwnership address has
    // been resolved by the AOB scanner; used as the dynamic vtable anchor.
    static void SetOwnershipAnchor(void* address);

    // Context note: which AppID the client is currently serving calls for
    static void NoteClientAppContext(uint32_t appId);

    // Shared dispatch for both factory hooks: logs and wraps a captured instance.
    static void* HandleFactoryResult(const char* name, void* result, const char* factory);

private:
    static void HookVTable(void* instance, const char* name, size_t index,
                           void* hookFunc, void** origFunc);
    static void WrapCaptured(void* instance, const char* version);
    static void WrapFamily(void* instance, const char* tag, const std::vector<VTableEntry>& entries);
    static void WrapClientUser(void* clientUser);
    static void WrapClientUtils(void* clientUtils);
    // Called with the interface lock held. Returns false while the anchor is pending.
    static bool TryHookClientUserLocked(void* clientUser);
};

} // namespace IceBreaker
