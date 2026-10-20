#include "PatchEngine.h"
#include "Scanner.h"
#include "Patterns.h"
#include "HookManager.h"
#include "../Steam/AppManager.h"
#include "../Steam/Interfaces.h"
#include <sstream>
#include <cstdint>

namespace IceBreaker {

std::unordered_map<std::string, uintptr_t> PatchEngine::s_resolved;

uintptr_t PatchEngine::ResolvedAddress(const std::string& name) {
    auto it = s_resolved.find(name);
    return it != s_resolved.end() ? it->second : 0;
}

void PatchEngine::CacheResolved(const std::string& name, uintptr_t addr) {
    if (addr) s_resolved[name] = addr;
}

static uintptr_t ClientModule() {
    static uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(L"steamclient64.dll"));
    return base;
}

uintptr_t PatchEngine::ClientBase() { return ClientModule(); }

uintptr_t PatchEngine::UIBase() {
    return reinterpret_cast<uintptr_t>(GetModuleHandleW(L"steamui.dll"));
}

static std::string Hex(uintptr_t addr) {
    std::ostringstream out;
    out << "0x" << std::hex << addr;
    return out.str();
}

// ── steamui.dll: library visibility ─────────────────────────────────
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

// ── steamclient64.dll: IClientUser::CheckAppOwnership ────────────────
// Layout mirrored from OpenSteamTool's Steam/Structs.h. Only the fields the
// unlock path writes are relied upon; the rest exist to keep offsets exact.
typedef uint32_t PackageId_t;

enum EAppReleaseState : uint32_t {
    AppReleaseState_UnknownApp = 0,
    AppReleaseState_Unavailable = 1,
    AppReleaseState_Prerelease = 2,
    AppReleaseState_PreloadOnly = 3,
    AppReleaseState_Released = 4,
};

struct AppOwnership {
    PackageId_t PackageId;
    uint32_t ReleaseState;
    uint32_t SteamId32;
    uint32_t MasterSubscriptionAppID;
    uint32_t TrialSeconds;
    uint32_t ExistInPackageNums;
    char PurchaseCountryCode[4];
    uint32_t TimeStamp;
    uint32_t TimeExpire;
    bool bOwnsLicense;
    bool bLicenseExpired;
    bool bIsPermanent;
    bool bLowViolence;
    bool bFreeLicense;
    bool bRegionRestricted;
    bool bFromFreeWeekend;
    bool bLicenseLocked;
    bool bLicensePending;
    bool bRetailLicense;
    bool bAutoGrant;
    bool bLicensePermanent;
    bool bGuestPass;
    bool bBorrowed;
    bool bAnySiteLicense;
    bool bAllSiteLicenses;
    bool bAllActivationRequired;
    bool bFamilyShared;
};

typedef bool (*pfnCheckAppOwnership)(void* pThis, uint32_t appId, AppOwnership* pOwn);
static pfnCheckAppOwnership oCheckAppOwnership = nullptr;

static bool Hook_CheckAppOwnership(void* pThis, uint32_t appId, AppOwnership* pOwn) {
    bool result = oCheckAppOwnership ? oCheckAppOwnership(pThis, appId, pOwn) : false;

    if (AppManager::Get().IsAppUnlocked(appId)) {
        if (pOwn) {
            // Actually owned (vendored via >1 package match) — leave Steam's data alone.
            if (!(result && pOwn->ExistInPackageNums > 1)) {
                pOwn->PackageId = 0;                      // injected package
                pOwn->ReleaseState = AppReleaseState_Released;
                pOwn->bOwnsLicense = true;
                pOwn->bFreeLicense = false;               // hides the library "free" badge
            }
        }
        return true;
    }
    return result;
}

// ── steamui.dll: CSteamUIAppController::GetAppByID capture ───────────
typedef void* (*pfnGetAppByID)(void* pThis, uint32_t appId, bool bCreate);
static pfnGetAppByID oGetAppByID = nullptr;
static void* g_appController = nullptr;

static void* Hook_GetAppByID(void* pThis, uint32_t appId, bool bCreate) {
    // Capture-only (OST semantics): remember the library controller instance and
    // pass through. The resolved RVA also serves as a future vtable anchor.
    if (!g_appController) {
        g_appController = pThis;
        HookManager::Log("GetAppByID: captured CSteamUIAppController instance.");
    }
    return oGetAppByID ? oGetAppByID(pThis, appId, bCreate) : nullptr;
}

// ── resolution bookkeeping ────────────────────────────────────────────
static void Resolve(const PatternDefinition& pat, uintptr_t base, const char* tag) {
    if (PatchEngine::ResolvedAddress(pat.name)) return;
    uintptr_t addr = Scanner::ScanModule(reinterpret_cast<HMODULE>(base), pat.pattern);
    if (!addr) {
        HookManager::Log(std::string(tag) + ": pattern not found: " + pat.name);
        return;
    }
    PatchEngine::CacheResolved(pat.name, addr);
    HookManager::Log(std::string(tag) + ": found " + pat.name + " at " + Hex(addr));
}

void PatchEngine::ApplyInMemoryPatches() {
    const uintptr_t ui = reinterpret_cast<uintptr_t>(GetModuleHandleW(L"steamui.dll"));
    const uintptr_t client = ClientModule();
    HookManager::Log("Scanning in-memory patterns (steamui=" + Hex(ui) + " steamclient64=" + Hex(client) + ")");

    if (ui) {
        for (const auto& pat : g_SteamUIPatterns) {
            Resolve(pat, ui, "steamui");
        }
        if (auto addr = ResolvedAddress("ShouldShowAppInLibrary")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_ShouldShowAppInLibrary),
                                    reinterpret_cast<void**>(&oShouldShowAppInLibrary),
                                    "ShouldShowAppInLibrary");
        }
        if (auto addr = ResolvedAddress("GetAppByID")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_GetAppByID),
                                    reinterpret_cast<void**>(&oGetAppByID),
                                    "GetAppByID");
        }
    }

    if (client) {
        for (const auto& pat : g_SteamClientPatterns) {
            Resolve(pat, client, "steamclient64");
        }
        if (auto addr = ResolvedAddress("CheckAppOwnership")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_CheckAppOwnership),
                                    reinterpret_cast<void**>(&oCheckAppOwnership),
                                    "CheckAppOwnership");
        }

        // Expose resolved anchors to the vtable dispatcher: once CheckAppOwnership's
        // address is known, a captured IClientUser vtable can locate its slot
        // dynamically (no hardcoded vtable offset).
        if (auto addr = ResolvedAddress("CheckAppOwnership")) {
            Interfaces::SetOwnershipAnchor(reinterpret_cast<void*>(addr));
        }
    }

    HookManager::Log("In-memory patching complete. Resolved " +
                     std::to_string(s_resolved.size()) + " patterns.");
}

} // namespace IceBreaker
