#include "PatchEngine.h"
#include "Scanner.h"
#include "Patterns.h"
#include "HookManager.h"
#include "../Steam/AppManager.h"
#include "../Steam/Interfaces.h"
#include <sstream>
#include <cstdint>
#include <vector>

namespace IceBreaker {

std::unordered_map<std::string, uintptr_t> PatchEngine::s_resolved;

uintptr_t PatchEngine::ResolvedAddress(const std::string& name) {
    auto it = s_resolved.find(name);
    return it != s_resolved.end() ? it->second : 0;
}

void PatchEngine::CacheResolved(const std::string& name, uintptr_t addr) {
    if (addr) s_resolved[name] = addr;
}

uintptr_t PatchEngine::ClientBase() {
    static uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(L"steamclient64.dll"));
    return base;
}

uintptr_t PatchEngine::UIBase() {
    return reinterpret_cast<uintptr_t>(GetModuleHandleW(L"steamui.dll"));
}

static std::string Hex(uintptr_t addr) {
    std::ostringstream out;
    out << "0x" << std::hex << addr;
    return out.str();
}

// ── steamclient64: CheckAppOwnership hook ─────────────────────────────
// Full AppOwnership layout matching steamclient64.dll.
// Setting bBorrowed and bFamilyShared to false prevents Steam from flagging
// unlocked games with "From your Steam Family library".
struct AppOwnership {
    uint32_t PackageId;
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

typedef bool (*pfnCheckAppOwnership_t)(void* pThis, uint32_t appId, AppOwnership* pOwn);
static pfnCheckAppOwnership_t oCheckAppOwnership = nullptr;

static bool Hook_CheckAppOwnership(void* pThis, uint32_t appId, AppOwnership* pOwn) {
    bool result = oCheckAppOwnership ? oCheckAppOwnership(pThis, appId, pOwn) : false;

    if (AppManager::Get().IsAppUnlocked(appId)) {
        if (pOwn) {
            pOwn->bOwnsLicense = true;
            pOwn->ReleaseState = 4; // AppReleaseState_Released
            pOwn->bIsPermanent = true;
            pOwn->bLicensePermanent = true;
            pOwn->bFreeLicense = false;
            pOwn->bBorrowed = false;
            pOwn->bFamilyShared = false;
            pOwn->bGuestPass = false;
            pOwn->bLicenseLocked = false;
            pOwn->bLicensePending = false;
            return true;
        }
    }
    return result;
}

// ── steamui.dll: library visibility hook ──────────────────────────────
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

// ── resolution bookkeeping ────────────────────────────────────────────
static void Resolve(const PatternDefinition& pat, uintptr_t base, const char* tag) {
    if (PatchEngine::ResolvedAddress(pat.name)) return;
    uintptr_t addr = Scanner::ScanModule(reinterpret_cast<HMODULE>(base), pat.pattern);
    if (!addr) {
        HookManager::Log(std::string(tag) + ": pattern not matched: " + pat.name + " (non-fatal)");
        return;
    }
    PatchEngine::CacheResolved(pat.name, addr);
    HookManager::Log(std::string(tag) + ": found " + pat.name + " at " + Hex(addr));
}

void PatchEngine::ApplyInMemoryPatches() {
    const uintptr_t ui = UIBase();
    const uintptr_t client = ClientBase();
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
            Interfaces::SetOwnershipAnchor(reinterpret_cast<void*>(addr));
        }
    }

    HookManager::Log("In-memory patching complete. Resolved " +
                     std::to_string(s_resolved.size()) + " patterns.");
}

} // namespace IceBreaker
