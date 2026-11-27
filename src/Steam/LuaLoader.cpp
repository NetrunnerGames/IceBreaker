#include "LuaLoader.h"
#include "AppManager.h"
#include "../Core/HookManager.h"
#include "../Core/PatchEngine.h"
#include <fstream>
#include <regex>
#include <string>
#include <thread>
#include <windows.h>
#include <vector>
#include <chrono>
#include <mutex>
#include <condition_variable>

namespace IceBreaker {

std::atomic<bool> LuaLoader::s_stopFlag{false};
std::atomic<bool> LuaLoader::s_watcherRunning{false};

static std::mutex g_reloadMutex;
static std::chrono::steady_clock::time_point g_lastReloadTime{};
static std::atomic<uint64_t> g_reloadSeq{0};

static std::mutex g_lifecycleMutex;
static std::mutex g_debounceMutex;
static std::condition_variable g_debounceCv;
static bool g_trailingScheduled = false;
static uint64_t g_trailingForSeq = 0;
static std::thread g_debounceThread;
static std::thread g_watcherThread;

static uint8_t ParseHexNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

static std::vector<uint8_t> ParseHex64(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() != 64) return bytes;
    bytes.reserve(32);
    for (size_t i = 0; i < 64; i += 2) {
        bytes.push_back(static_cast<uint8_t>((ParseHexNibble(hex[i]) << 4) | ParseHexNibble(hex[i + 1])));
    }
    return bytes;
}

std::wstring LuaLoader::GetSteamPluginDir() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastSlash = path.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        return path.substr(0, lastSlash) + L"\\config\\stplug-in";
    }
    return L"";
}

void LuaLoader::ParseLuaFile(const std::wstring& filePath,
                             std::unordered_map<uint32_t, uint32_t>& appToPackage,
                             std::unordered_map<uint32_t, std::unordered_set<uint32_t>>& appDLCs,
                             std::unordered_map<uint32_t, std::vector<uint8_t>>& depotKeys,
                             std::unordered_map<uint32_t, uint64_t>& accessTokens) {
    std::ifstream file(filePath);
    if (!file.is_open()) return;

    // Derive base app ID from filename (e.g. 552520.lua -> 552520)
    uint32_t fileBaseAppId = 0;
    size_t lastSlash = filePath.find_last_of(L"\\/");
    std::wstring fileName = (lastSlash != std::wstring::npos) ? filePath.substr(lastSlash + 1) : filePath;
    size_t dotPos = fileName.find(L'.');
    if (dotPos != std::wstring::npos) {
        std::wstring baseNum = fileName.substr(0, dotPos);
        try { fileBaseAppId = std::stoul(baseNum); } catch (...) {}
    }

    std::string line;
    std::regex addAppKeyRegex(R"(addappid\s*\(\s*(\d+)(?:\s*,\s*\d+\s*,\s*["']([a-fA-F0-9]{64})["'])?)", std::regex_constants::icase);
    std::regex dlcRegex(R"((?:set_dlc|add_dlc|setdlc)\s*\(\s*(\d+)\s*,\s*(\d+))", std::regex_constants::icase);
    std::regex addTokenRegex(R"(addtoken\s*\(\s*(\d+)\s*,\s*["'](\d+)["']\s*\))", std::regex_constants::icase);
    std::regex rawAppRegex(R"(app(?:id)?\s*=\s*(\d+))", std::regex_constants::icase);

    while (std::getline(file, line)) {
        std::smatch match;
        try {
            if (std::regex_search(line, match, addAppKeyRegex)) {
                uint32_t appId = static_cast<uint32_t>(std::stoul(match[1].str()));
                uint32_t pkgId = fileBaseAppId ? fileBaseAppId : appId;
                appToPackage[appId] = pkgId;
                if (match.size() > 2 && match[2].matched) {
                    std::string keyHex = match[2].str();
                    std::vector<uint8_t> keyBytes = ParseHex64(keyHex);
                    if (keyBytes.size() == 32) {
                        depotKeys[appId] = keyBytes;
                    }
                }
            } else if (std::regex_search(line, match, addTokenRegex)) {
                uint32_t appId = static_cast<uint32_t>(std::stoul(match[1].str()));
                uint64_t token = std::stoull(match[2].str());
                if (token != 0) accessTokens[appId] = token;
            } else if (std::regex_search(line, match, dlcRegex)) {
                uint32_t appId = static_cast<uint32_t>(std::stoul(match[1].str()));
                uint32_t dlcId = static_cast<uint32_t>(std::stoul(match[2].str()));
                appDLCs[appId].insert(dlcId);
                appToPackage[dlcId] = appId;
            } else if (std::regex_search(line, match, rawAppRegex)) {
                uint32_t appId = static_cast<uint32_t>(std::stoul(match[1].str()));
                uint32_t pkgId = fileBaseAppId ? fileBaseAppId : appId;
                appToPackage[appId] = pkgId;
            }
        } catch (...) {
            // Ignore malformed or out-of-range numeric entries on this line
        }
    }
}

void LuaLoader::DebounceWorkerLoop() {
    while (true) {
        std::chrono::steady_clock::time_point target;
        uint64_t scheduledSeq = 0;
        {
            std::unique_lock<std::mutex> lk(g_debounceMutex);
            g_debounceCv.wait(lk, []() {
                return s_stopFlag.load() || g_trailingScheduled;
            });
            if (s_stopFlag.load()) break;

            target = g_lastReloadTime + std::chrono::milliseconds(505);
            scheduledSeq = g_trailingForSeq;

            g_debounceCv.wait_until(lk, target, []() {
                return s_stopFlag.load();
            });
            if (s_stopFlag.load()) break;
            g_trailingScheduled = false;
        }

        // Only execute trailing reload if no other reload already completed since it was scheduled
        if (g_reloadSeq.load() == scheduledSeq) {
            ReloadAll();
        }
    }
}

void LuaLoader::ReloadAll() {
    std::lock_guard<std::mutex> lock(g_reloadMutex);

    // In-DLL debounce (500ms) to coalesce rapid file watcher / IPC events without dropping trailing edits
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastReloadTime).count();
    if (elapsed < 500 && g_lastReloadTime != std::chrono::steady_clock::time_point{}) {
        if (!s_stopFlag.load()) {
            {
                std::lock_guard<std::mutex> dlk(g_debounceMutex);
                g_trailingScheduled = true;
                g_trailingForSeq = g_reloadSeq.load();
            }
            {
                std::lock_guard<std::mutex> llk(g_lifecycleMutex);
                if (!g_debounceThread.joinable() && !s_stopFlag.load()) {
                    g_debounceThread = std::thread(DebounceWorkerLoop);
                }
            }
            g_debounceCv.notify_all();
        }
        HookManager::Log("ReloadAll: debounced (called " + std::to_string(elapsed) + "ms since last reload; scheduled trailing sync)");
        return;
    }
    g_lastReloadTime = now;
    g_reloadSeq.fetch_add(1);

    std::wstring pluginDir = GetSteamPluginDir();
    if (pluginDir.empty()) return;

    std::wstring searchPattern = pluginDir + L"\\*.lua";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
    DWORD findErr = (hFind == INVALID_HANDLE_VALUE) ? GetLastError() : ERROR_SUCCESS;

    if (hFind == INVALID_HANDLE_VALUE && findErr != ERROR_FILE_NOT_FOUND) {
        return;
    }

    std::unordered_map<uint32_t, uint32_t> scannedAppToPackage;
    std::unordered_map<uint32_t, std::unordered_set<uint32_t>> scannedAppDLCs;
    std::unordered_map<uint32_t, std::vector<uint8_t>> scannedDepotKeys;
    std::unordered_map<uint32_t, uint64_t> scannedAccessTokens;

    size_t count = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::wstring fullPath = pluginDir + L"\\" + findData.cFileName;
                ParseLuaFile(fullPath, scannedAppToPackage, scannedAppDLCs, scannedDepotKeys, scannedAccessTokens);
                count++;
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }

    // Reconcile against current in-memory state: calculate diff atomically
    bool changed = AppManager::Get().ReconcileState(scannedAppToPackage, scannedAppDLCs, scannedDepotKeys, scannedAccessTokens);

    HookManager::Log("Scanned " + std::to_string(count) + " Lua manifests. Total unlocked AppIDs: " +
                     std::to_string(AppManager::Get().GetUnlockedCount()) +
                     " (state change: " + (changed ? "YES" : "NO") + ")");

    // Only notify Steam when something actually changed!
    if (changed) {
        HookManager::Log("Lua manifests changed on disk: triggering license change notification.");
        PatchEngine::NotifyLicenseChanged(false);
    }
}

bool LuaLoader::LoadPluginManifests() {
    std::wstring pluginDir = GetSteamPluginDir();
    if (pluginDir.empty()) return false;

    // Narrow log conversion is best-effort for the ASCII-only Steam-root case.
    std::string dirNarrow;
    dirNarrow.reserve(pluginDir.size());
    for (wchar_t ch : pluginDir) dirNarrow.push_back(static_cast<char>(ch));
    HookManager::Log("Scanning for manifests in: " + dirNarrow);

    ReloadAll();
    if (AppManager::Get().GetUnlockedCount() == 0) {
        HookManager::Log("No .lua files found in plugin directory.");
        return false;
    }
    return true;
}

void LuaLoader::WatcherLoop(std::wstring pluginDir) {
    HANDLE hChange = FindFirstChangeNotificationW(pluginDir.c_str(), FALSE,
                                                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME);
    if (hChange == INVALID_HANDLE_VALUE) return;

    while (!s_stopFlag.load()) {
        DWORD wait = WaitForSingleObject(hChange, 500);
        if (s_stopFlag.load()) break;
        if (wait == WAIT_OBJECT_0) {
            // Editors often write multiple times in quick succession; interruptible 500ms coalesce.
            {
                std::unique_lock<std::mutex> lk(g_debounceMutex);
                g_debounceCv.wait_for(lk, std::chrono::milliseconds(500), []() {
                    return s_stopFlag.load();
                });
            }
            if (s_stopFlag.load()) break;
            if (!FindNextChangeNotification(hChange)) break;
            ReloadAll();
        }
    }
    FindCloseChangeNotification(hChange);
}

void LuaLoader::StartReloadWatcher() {
    std::wstring pluginDir = GetSteamPluginDir();
    if (pluginDir.empty()) return;
    std::lock_guard<std::mutex> lk(g_lifecycleMutex);
    bool expected = false;
    if (!s_watcherRunning.compare_exchange_strong(expected, true)) return; // already running
    if (g_watcherThread.joinable()) {
        g_watcherThread.join();
    }
    s_stopFlag.store(false);
    g_watcherThread = std::thread(WatcherLoop, pluginDir);
    HookManager::Log("Manifest hot-reload watcher started.");
}

void LuaLoader::StopReloadWatcher() {
    s_stopFlag.store(true);
    s_watcherRunning.store(false);
    g_debounceCv.notify_all();

    std::thread watcherToJoin;
    std::thread debounceToJoin;
    {
        std::lock_guard<std::mutex> lk(g_lifecycleMutex);
        watcherToJoin = std::move(g_watcherThread);
        debounceToJoin = std::move(g_debounceThread);
    }
    if (watcherToJoin.joinable()) watcherToJoin.join();
    if (debounceToJoin.joinable()) debounceToJoin.join();
}

} // namespace IceBreaker
