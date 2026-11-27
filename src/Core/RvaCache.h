#pragma once
#include <windows.h>
#include <wininet.h>
#include <psapi.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <shlwapi.h>
#include <thread>
#include <mutex>
#include <cctype>
#include "HookManager.h"
#include "Scanner.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")

namespace IceBreaker {

/// <summary>
/// Manages $O(1)$ fast-path RVA resolution based on the module's unique PE header signature
/// (TimeDateStamp + SizeOfImage). Integrates with Cloudflare KV edge cache:
/// 1. Local disk cache lookup (0 ms, cached in memory)
/// 2. Remote Cloudflare KV query if local cache & local AOB miss (bounded timeout, HTTP 2xx + bounds checked)
/// 3. Async background submission to Cloudflare KV when local heuristic recovers a new build
/// </summary>
class RvaCache {
public:
    static constexpr const char* KV_API_BASE = "https://bots.netrunnergames.workers.dev/api/rva";
    static constexpr const char* IB_SECRET = "ib_netrunner_sec_99a8b7";

    static std::string GetModuleBuildId(HMODULE hMod) {
        if (!hMod) return "";
        MODULEINFO modInfo = { 0 };
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) return "";
        if (modInfo.SizeOfImage < sizeof(IMAGE_DOS_HEADER)) return "";

        const uint8_t* base = reinterpret_cast<const uint8_t*>(hMod);
        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return "";
        if (dosHeader->e_lfanew <= 0 ||
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > modInfo.SizeOfImage) {
            return "";
        }

        auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return "";

        uint32_t timeStamp = ntHeaders->FileHeader.TimeDateStamp;
        uint32_t sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0')
           << std::setw(8) << timeStamp << "-"
           << std::setw(8) << sizeOfImage;
        return ss.str();
    }

    static bool IsValidCodeRva(HMODULE hMod, uintptr_t rva) {
        if (!hMod || rva == 0) return false;
        uintptr_t base = reinterpret_cast<uintptr_t>(hMod);
        if (rva > (UINTPTR_MAX - base)) return false;
        uintptr_t target = base + rva;
        for (const auto& [rangeBase, rangeSize] : Scanner::ExecutableRanges(hMod)) {
            if (target >= rangeBase && target < rangeBase + rangeSize) {
                return true;
            }
        }
        return false;
    }

    static uintptr_t GetCachedLocalAddress(HMODULE hMod, const std::string& funcName) {
        if (!hMod) return 0;
        std::string buildId = GetModuleBuildId(hMod);
        if (buildId.empty()) return 0;

        uintptr_t rva = 0;
        {
            std::lock_guard<std::mutex> lock(CacheMutex());
            EnsureLoadedLocked();
            auto bIt = CacheData().find(buildId);
            if (bIt != CacheData().end()) {
                auto fIt = bIt->second.find(funcName);
                if (fIt != bIt->second.end()) {
                    rva = fIt->second;
                }
            }
        }
        if (rva && IsValidCodeRva(hMod, rva)) {
            return reinterpret_cast<uintptr_t>(hMod) + rva;
        }
        return 0;
    }

    static uintptr_t FetchRemoteAddress(HMODULE hMod, const std::string& funcName) {
        if (!hMod) return 0;
        std::string buildId = GetModuleBuildId(hMod);
        if (buildId.empty()) return 0;

        {
            std::lock_guard<std::mutex> lock(CacheMutex());
            if (!CheckedRemoteBuilds().insert(buildId).second) {
                return 0;
            }
        }

        std::string kvData = FetchFromKV(buildId);
        if (!kvData.empty()) {
            MergeIntoLocalCache(buildId, kvData);
            uintptr_t addr = GetCachedLocalAddress(hMod, funcName);
            if (addr) {
                HookManager::Log("RvaCache: Resolved " + funcName + " via Cloudflare KV for build " + buildId);
                return addr;
            }
        }
        return 0;
    }

    static uintptr_t GetCachedAddress(HMODULE hMod, const std::string& funcName) {
        if (uintptr_t localAddr = GetCachedLocalAddress(hMod, funcName)) {
            return localAddr;
        }
        return FetchRemoteAddress(hMod, funcName);
    }

    static void SaveAddress(HMODULE hMod, const std::string& funcName, uintptr_t funcAddress) {
        if (!hMod || !funcAddress) return;
        std::string buildId = GetModuleBuildId(hMod);
        if (buildId.empty()) return;

        uintptr_t base = reinterpret_cast<uintptr_t>(hMod);
        if (funcAddress < base) return;
        uintptr_t rva = funcAddress - base;
        if (!IsValidCodeRva(hMod, rva)) return;

        {
            std::lock_guard<std::mutex> lock(CacheMutex());
            EnsureLoadedLocked();
            auto& entry = CacheData()[buildId][funcName];
            if (entry == rva) return; // Already cached with identical RVA
            entry = rva;
            SaveFile(GetRvaCachePath(), SerializeRvaMap(CacheData()));
        }
        HookManager::Log("RvaCache: Saved " + funcName + " (RVA 0x" + Hex(rva) + ") for build " + buildId);

        // Submit to Cloudflare KV asynchronously in background thread so user flow never blocks
        SubmitToKVAsync(buildId, funcName, rva);
    }

private:
    using RvaMap = std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>>;

    static std::mutex& CacheMutex() {
        static std::mutex m;
        return m;
    }

    static RvaMap& CacheData() {
        static RvaMap data;
        return data;
    }

    static bool& CacheLoaded() {
        static bool loaded = false;
        return loaded;
    }

    static std::unordered_set<std::string>& CheckedRemoteBuilds() {
        static std::unordered_set<std::string> checked;
        return checked;
    }

    static void EnsureLoadedLocked() {
        if (!CacheLoaded()) {
            std::string content = LoadFile(GetRvaCachePath());
            CacheData() = ParseRvaJson(content);
            CacheLoaded() = true;
        }
    }

    static std::string Hex(uintptr_t val) {
        std::ostringstream ss;
        ss << std::hex << val;
        return ss.str();
    }

    static std::wstring GetRvaCachePath() {
        wchar_t steamPath[MAX_PATH] = { 0 };
        DWORD pathSize = sizeof(steamPath);
        if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath",
                         RRF_RT_REG_SZ, nullptr, steamPath, &pathSize) == ERROR_SUCCESS) {
            return std::wstring(steamPath) + L"\\config\\icebreaker_rva_cache.json";
        }
        wchar_t currentDir[MAX_PATH] = { 0 };
        GetModuleFileNameW(nullptr, currentDir, MAX_PATH);
        PathRemoveFileSpecW(currentDir);
        return std::wstring(currentDir) + L"\\config\\icebreaker_rva_cache.json";
    }

    static std::string LoadFile(const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return "";

        DWORD size = GetFileSize(hFile, nullptr);
        if (size == 0 || size == INVALID_FILE_SIZE || size > 2 * 1024 * 1024) {
            CloseHandle(hFile);
            return "";
        }
        std::string buf(size, '\0');
        DWORD read = 0;
        if (!ReadFile(hFile, &buf[0], size, &read, nullptr)) {
            CloseHandle(hFile);
            return "";
        }
        buf.resize(read);
        CloseHandle(hFile);
        return buf;
    }

    static void SaveFile(const std::wstring& path, const std::string& content) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hFile, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
            CloseHandle(hFile);
        }
    }

    static std::string SerializeRvaMap(const RvaMap& data) {
        std::ostringstream ss;
        ss << "{\n";
        size_t bCount = 0;
        for (const auto& [bId, funcs] : data) {
            ss << "  \"" << bId << "\": {\n";
            size_t fCount = 0;
            for (const auto& [fName, fRva] : funcs) {
                ss << "    \"" << fName << "\": \"0x" << std::hex << fRva << "\""
                   << (fCount + 1 < funcs.size() ? "," : "") << "\n";
                fCount++;
            }
            ss << "  }" << (bCount + 1 < data.size() ? "," : "") << "\n";
            bCount++;
        }
        ss << "}\n";
        return ss.str();
    }

    static void ApplyWinInetTimeouts(HINTERNET hInternet, DWORD timeoutMs = 2000) {
        if (!hInternet) return;
        InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
        InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
        InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
    }

    static bool IsHttpSuccess(HINTERNET hRequest) {
        DWORD statusCode = 0;
        DWORD len = sizeof(statusCode);
        if (!HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &len, nullptr)) {
            return false;
        }
        return statusCode >= 200 && statusCode < 300;
    }

    static std::string FetchFromKV(const std::string& buildId) {
        std::string url = std::string(KV_API_BASE) + "?build=" + buildId;
        HINTERNET hInternet = InternetOpenA("IceBreaker-KV/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInternet) return "";
        ApplyWinInetTimeouts(hInternet, 2000);

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE;
        HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, flags, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            return "";
        }
        ApplyWinInetTimeouts(hUrl, 2000);

        if (!IsHttpSuccess(hUrl)) {
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return "";
        }

        std::string response;
        char buffer[2048];
        DWORD bytesRead = 0;
        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            if (response.size() + bytesRead > 256 * 1024) break;
            response.append(buffer, bytesRead);
        }

        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return response;
    }

    static void SkipWs(const std::string& s, size_t& pos) {
        while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\r' || s[pos] == '\n')) {
            ++pos;
        }
    }

    static bool ReadJsonString(const std::string& s, size_t& pos, std::string& out) {
        SkipWs(s, pos);
        if (pos >= s.size() || s[pos] != '"') return false;
        ++pos;
        out.clear();
        while (pos < s.size()) {
            char c = s[pos++];
            if (c == '\\' && pos < s.size()) {
                out.push_back(s[pos++]);
                continue;
            }
            if (c == '"') return true;
            out.push_back(c);
        }
        return false;
    }

    static bool ParseHexRva(const std::string& valStr, uintptr_t& outRva) {
        if (valStr.size() <= 2 || valStr[0] != '0' || (valStr[1] != 'x' && valStr[1] != 'X')) {
            return false;
        }
        const size_t start = 2;
        if ((valStr.size() - start) > 16) return false;
        for (size_t i = start; i < valStr.size(); ++i) {
            if (!std::isxdigit(static_cast<unsigned char>(valStr[i]))) return false;
        }
        try {
            size_t idx = 0;
            unsigned long long val = std::stoull(valStr.substr(start), &idx, 16);
            if (idx != (valStr.size() - start) || val == 0) return false;
            outRva = static_cast<uintptr_t>(val);
            return true;
        } catch (...) {
            return false;
        }
    }

    static void MergeIntoLocalCache(const std::string& buildId, const std::string& kvJson) {
        size_t pos = 0;
        SkipWs(kvJson, pos);
        if (pos >= kvJson.size() || kvJson[pos] != '{') return;
        ++pos;

        std::unordered_map<std::string, uintptr_t> parsed;
        while (pos < kvJson.size()) {
            SkipWs(kvJson, pos);
            if (pos >= kvJson.size() || kvJson[pos] == '}') break;
            if (kvJson[pos] == ',') { ++pos; continue; }

            std::string key;
            if (!ReadJsonString(kvJson, pos, key)) break;
            SkipWs(kvJson, pos);
            if (pos >= kvJson.size() || kvJson[pos] != ':') break;
            ++pos;
            SkipWs(kvJson, pos);
            if (pos >= kvJson.size() || kvJson[pos] != '"') break;

            std::string val;
            if (!ReadJsonString(kvJson, pos, val)) break;

            uintptr_t rva = 0;
            if (!key.empty() && ParseHexRva(val, rva)) {
                parsed[key] = rva;
            }
        }

        if (parsed.empty()) return;

        std::lock_guard<std::mutex> lock(CacheMutex());
        EnsureLoadedLocked();
        for (const auto& [k, rva] : parsed) {
            CacheData()[buildId][k] = rva;
        }
        SaveFile(GetRvaCachePath(), SerializeRvaMap(CacheData()));
    }

    static void SubmitToKVAsync(const std::string& buildId, const std::string& funcName, uintptr_t rva) {
        std::thread([buildId, funcName, rva]() {
            HINTERNET hInternet = InternetOpenA("IceBreaker-KV/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
            if (!hInternet) return;
            ApplyWinInetTimeouts(hInternet, 2000);

            HINTERNET hConnect = InternetConnectA(hInternet, "bots.netrunnergames.workers.dev",
                                                  INTERNET_DEFAULT_HTTPS_PORT, nullptr, nullptr,
                                                  INTERNET_SERVICE_HTTP, 0, 0);
            if (!hConnect) {
                InternetCloseHandle(hInternet);
                return;
            }

            HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/api/rva", nullptr, nullptr,
                                                 nullptr, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
            if (hRequest) {
                ApplyWinInetTimeouts(hRequest, 2000);
                std::string headers = "Content-Type: application/json\r\nX-IceBreaker-Token: " + std::string(IB_SECRET) + "\r\n";
                std::ostringstream body;
                body << "{\"buildId\":\"" << buildId << "\",\"rvas\":{\"" << funcName << "\":\"0x" << std::hex << rva << "\"}}";
                std::string bodyStr = body.str();

                HttpSendRequestA(hRequest, headers.c_str(), static_cast<DWORD>(headers.length()),
                                 const_cast<char*>(bodyStr.c_str()), static_cast<DWORD>(bodyStr.length()));
                InternetCloseHandle(hRequest);
            }
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
        }).detach();
    }

    static RvaMap ParseRvaJson(const std::string& json) {
        RvaMap result;
        if (json.empty()) return result;

        size_t pos = 0;
        SkipWs(json, pos);
        if (pos >= json.size() || json[pos] != '{') return result;
        ++pos;

        while (pos < json.size()) {
            SkipWs(json, pos);
            if (pos >= json.size() || json[pos] == '}') break;
            if (json[pos] == ',') { ++pos; continue; }

            std::string buildId;
            if (!ReadJsonString(json, pos, buildId)) break;
            SkipWs(json, pos);
            if (pos >= json.size() || json[pos] != ':') break;
            ++pos;
            SkipWs(json, pos);
            if (pos >= json.size() || json[pos] != '{') break;
            ++pos;

            while (pos < json.size()) {
                SkipWs(json, pos);
                if (pos >= json.size() || json[pos] == '}') {
                    if (pos < json.size()) ++pos;
                    break;
                }
                if (json[pos] == ',') { ++pos; continue; }

                std::string fnName;
                if (!ReadJsonString(json, pos, fnName)) break;
                SkipWs(json, pos);
                if (pos >= json.size() || json[pos] != ':') break;
                ++pos;

                std::string valStr;
                if (!ReadJsonString(json, pos, valStr)) break;

                uintptr_t rva = 0;
                if (!buildId.empty() && !fnName.empty() && ParseHexRva(valStr, rva)) {
                    result[buildId][fnName] = rva;
                }
            }
        }
        return result;
    }

    static uintptr_t QueryRvaFromJson(const std::string& json, const std::string& buildId, const std::string& funcName) {
        auto map = ParseRvaJson(json);
        auto bIt = map.find(buildId);
        if (bIt != map.end()) {
            auto fIt = bIt->second.find(funcName);
            if (fIt != bIt->second.end()) {
                return fIt->second;
            }
        }
        return 0;
    }
};

} // namespace IceBreaker
