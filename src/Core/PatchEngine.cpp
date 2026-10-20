#include "PatchEngine.h"
#include "Scanner.h"
#include "Patterns.h"
#include "HookManager.h"
#include "../Steam/AppManager.h"
#include "../Steam/Interfaces.h"
#include <sstream>
#include <cstdint>
#include <algorithm>
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

// ── steamclient struct mirrors (kept in lockstep with steamclient64.dll) ──
typedef uint32_t AppId_t;
typedef uint32_t PackageId_t;

enum EAppReleaseState : uint32_t {
    AppReleaseState_UnknownApp = 0,
    AppReleaseState_Unavailable = 1,
    AppReleaseState_Prerelease = 2,
    AppReleaseState_PreloadOnly = 3,
    AppReleaseState_Released = 4,
};

enum EPackageStatus : uint32_t {
    PackageStatus_Available = 0,
    PackageStatus_Preorder = 1,
    PackageStatus_Unavailable = 2,
    PackageStatus_Invalid = 3,
};

template <typename T>
struct CUtlMemory {
    T* m_pMemory;
    uint32_t m_nAllocationCount;
    uint32_t m_nGrowSize;
};

template <typename T>
struct CUtlVector {
    CUtlMemory<T> m_Memory;
    uint32_t m_Size;
};

struct PackageInfo {
    PackageId_t PackageId;
    int32_t ChangeNumber;
    uint64_t PICS_token;
    uint32_t BillingType;
    uint32_t LicenseType;
    uint32_t Status;
    uint8_t SHA_1_Hash[20];
    void* pPackageInfoNodeBegin;
    void* pExtendNodeBegin;
    CUtlVector<AppId_t> AppIdVec;
    CUtlVector<AppId_t> DepotIdVec;
};

// ── steamclient64 hooks / resolvers ───────────────────────────────────
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

typedef bool (*pfnCheckAppOwnership_t)(void* pThis, uint32_t appId, AppOwnership* pOwn);
static pfnCheckAppOwnership_t oCheckAppOwnership = nullptr;

typedef PackageInfo* (*pfnGetPackageInfo)(void* pThis, uint32_t packageId, uint64_t accessToken);
typedef int64_t (*pfnMarkLicenseAsChanged)(void* pThis, uint32_t packageId, bool forceRefresh);
typedef bool (*pfnProcessPendingLicenseUpdates)(void* pThis);
typedef void* (*pfnCUtlMemoryGrow)(CUtlVector<AppId_t>* pVec, int growSize);

static pfnGetPackageInfo oGetPackageInfo = nullptr;
static pfnMarkLicenseAsChanged oMarkLicenseAsChanged = nullptr;
static pfnProcessPendingLicenseUpdates oProcessPendingLicenseUpdates = nullptr;
static pfnCUtlMemoryGrow oCUtlMemoryGrow = nullptr;

// OST constants: the injected package (0) must exist with this access token.
static constexpr PackageId_t kInjectedPackageId = 0;
static constexpr uint64_t kInjectedPkgAccessToken = 10660652434190618804ull;

static void* g_pCUser = nullptr;                 // IClientUser instance (CheckAppOwnership this)
static void* g_pCPackageInfo = nullptr;          // CPackageInfo instance (GetPackageInfo this)
static PackageInfo* g_pInjectedPackageInfo = nullptr;
static bool g_licenseInitialized = false;

// Hook: CPackageInfo::GetPackageInfo — capture the package store instance.
static PackageInfo* Hook_GetPackageInfo(void* pThis, uint32_t packageId, uint64_t accessToken) {
    if (pThis && !g_pCPackageInfo) {
        g_pCPackageInfo = pThis;
        HookManager::Log("GetPackageInfo: captured CPackageInfo instance.");
    }
    return oGetPackageInfo ? oGetPackageInfo(pThis, packageId, accessToken) : nullptr;
}

static bool TryProcessPendingLicenseRefresh() {
    if (!g_pCUser || !oMarkLicenseAsChanged || !oProcessPendingLicenseUpdates) {
        HookManager::Log("LicenseInjection: dependencies not ready, refresh skipped");
        return false;
    }
    oMarkLicenseAsChanged(g_pCUser, kInjectedPackageId, true);
    oProcessPendingLicenseUpdates(g_pCUser);
    HookManager::Log("LicenseInjection: marked package 0 as changed and processed updates");
    return true;
}

// Inject every unlocked AppID into the injected package's license vector, then
// force a license refresh so the client learns about newly "owned" apps.
static bool TryInitFakeLicenseOnce() {
    if (g_licenseInitialized) return true;
    if (!g_pCPackageInfo || !oGetPackageInfo || !oCUtlMemoryGrow) {
        return false;
    }

    PackageInfo* pPkg = oGetPackageInfo(g_pCPackageInfo, kInjectedPackageId, kInjectedPkgAccessToken);
    if (!pPkg) {
        HookManager::Log("LicenseInjection: GetPackageInfo returned null for injected package");
        return false;
    }
    if (!g_pInjectedPackageInfo) g_pInjectedPackageInfo = pPkg;
    if (pPkg->Status != PackageStatus_Available) {
        HookManager::Log("LicenseInjection: injected package status is not Available, skipping");
        return false;
    }

    std::vector<uint32_t> appIds;
    AppManager::Get().GetUnlockedApps(appIds);
    if (!appIds.empty()) {
        uint32_t oldSize = pPkg->AppIdVec.m_Size;
        if (oCUtlMemoryGrow(&pPkg->AppIdVec, static_cast<int>(appIds.size()))) {
            for (size_t i = 0; i < appIds.size(); ++i) {
                pPkg->AppIdVec.m_Memory.m_pMemory[oldSize + i] = appIds[i];
            }
            HookManager::Log("LicenseInjection: added " + std::to_string(appIds.size()) +
                             " apps to injected package " + std::to_string(kInjectedPackageId) +
                             " (old size " + std::to_string(oldSize) + ")");
        } else {
            HookManager::Log("LicenseInjection: failed to grow AppId vector");
            return false;
        }
    }

    g_licenseInitialized = true; // guard before refresh to prevent recursion
    TryProcessPendingLicenseRefresh();
    return true;
}

void PatchEngine::RefreshLicense() {
    if (!g_licenseInitialized || !g_pInjectedPackageInfo || !oCUtlMemoryGrow ||
        !oMarkLicenseAsChanged || !oProcessPendingLicenseUpdates || !g_pCUser) {
        return; // not initialized yet: next CheckAppOwnership picks up the new set
    }

    std::vector<uint32_t> appIds;
    AppManager::Get().GetUnlockedApps(appIds);
    if (appIds.empty()) return;

    // Add ids missing from the license vector (manifests may have changed).
    std::vector<uint32_t> missing;
    for (uint32_t id : appIds) {
        bool found = false;
        for (uint32_t i = 0; i < g_pInjectedPackageInfo->AppIdVec.m_Size; ++i) {
            if (g_pInjectedPackageInfo->AppIdVec.m_Memory.m_pMemory[i] == id) {
                found = true;
                break;
            }
        }
        if (!found) missing.push_back(id);
    }
    if (missing.empty()) return;

    uint32_t oldSize = g_pInjectedPackageInfo->AppIdVec.m_Size;
    if (oCUtlMemoryGrow(&g_pInjectedPackageInfo->AppIdVec, static_cast<int>(missing.size()))) {
        for (size_t i = 0; i < missing.size(); ++i) {
            g_pInjectedPackageInfo->AppIdVec.m_Memory.m_pMemory[oldSize + i] = missing[i];
        }
        HookManager::Log("LicenseInjection: hot-reload added " + std::to_string(missing.size()) + " app ids");
        TryProcessPendingLicenseRefresh();
    }
}

static bool Hook_CheckAppOwnership(void* pThis, uint32_t appId, AppOwnership* pOwn) {
    if (!g_pCUser) {
        g_pCUser = pThis;
        HookManager::Log("CheckAppOwnership: captured CUser instance.");
    }

    bool result = oCheckAppOwnership ? oCheckAppOwnership(pThis, appId, pOwn) : false;
    TryInitFakeLicenseOnce();

    if (AppManager::Get().IsAppUnlocked(appId)) {
        if (pOwn && !(result && pOwn->ExistInPackageNums > 1)) {
            // Not actually owned yet — override with the injected package license.
            pOwn->PackageId = kInjectedPackageId;
            pOwn->ReleaseState = AppReleaseState_Released;
            pOwn->bOwnsLicense = true;
            pOwn->bFreeLicense = false;
            return true;
        }
    }
    return result;
}

// ── steamui hooks ─────────────────────────────────────────────────────
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

typedef void* (*pfnGetAppByID)(void* pThis, uint32_t appId, bool bCreate);
static pfnGetAppByID oGetAppByID = nullptr;
static void* g_appController = nullptr;

static void* Hook_GetAppByID(void* pThis, uint32_t appId, bool bCreate) {
    // Capture-only (OST semantics): remember the library controller instance.
    if (!g_appController && pThis) {
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
        if (auto addr = ResolvedAddress("GetPackageInfo")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_GetPackageInfo),
                                    reinterpret_cast<void**>(&oGetPackageInfo),
                                    "GetPackageInfo");
        }
        if (auto addr = ResolvedAddress("CUtlMemoryGrow")) {
            oCUtlMemoryGrow = reinterpret_cast<pfnCUtlMemoryGrow>(addr);
        }
        if (auto addr = ResolvedAddress("MarkLicenseAsChanged")) {
            oMarkLicenseAsChanged = reinterpret_cast<pfnMarkLicenseAsChanged>(addr);
        }
        if (auto addr = ResolvedAddress("ProcessPendingLicenseUpdates")) {
            oProcessPendingLicenseUpdates = reinterpret_cast<pfnProcessPendingLicenseUpdates>(addr);
        }
        if (auto addr = ResolvedAddress("CheckAppOwnership")) {
            Interfaces::SetOwnershipAnchor(reinterpret_cast<void*>(addr));
        }
    }

    HookManager::Log("In-memory patching complete. Resolved " +
                     std::to_string(s_resolved.size()) + " patterns.");
}

} // namespace IceBreaker
