#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <windows.h>
#include <wininet.h>
#include <shlwapi.h>
#include <sstream>
#include <fstream>
#include "HookManager.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")

namespace IceBreaker {

class OtaClient {
public:
    static constexpr const char* OTA_URL = "https://raw.githubusercontent.com/NetrunnerGames/OTA/main/icebreaker_patterns.json";

    /// Attempts to fetch the latest patterns JSON from OTA endpoint.
    /// Falls back to local cached copy if offline.
    /// Returns map of pattern name -> vector of hex signatures.
    static std::unordered_map<std::string, std::vector<std::string>> FetchPatterns() {
        std::string jsonContent = DownloadJson(OTA_URL);
        std::wstring cachePath = GetCacheFilePath();

        if (!jsonContent.empty()) {
            SaveToCache(cachePath, jsonContent);
        } else {
            HookManager::Log("OTA: Network fetch failed or offline, loading from local cache...");
            jsonContent = LoadFromCache(cachePath);
        }

        if (jsonContent.empty()) {
            return {};
        }

        return ParsePatternsJson(jsonContent);
    }

private:
    static std::wstring GetCacheFilePath() {
        wchar_t steamPath[MAX_PATH] = { 0 };
        DWORD pathSize = sizeof(steamPath);
        if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath",
                         RRF_RT_REG_SZ, nullptr, steamPath, &pathSize) == ERROR_SUCCESS) {
            std::wstring cache = std::wstring(steamPath) + L"\\config\\icebreaker_patterns_cache.json";
            return cache;
        }

        wchar_t currentDir[MAX_PATH] = { 0 };
        GetModuleFileNameW(nullptr, currentDir, MAX_PATH);
        PathRemoveFileSpecW(currentDir);
        return std::wstring(currentDir) + L"\\config\\icebreaker_patterns_cache.json";
    }

    static void SaveToCache(const std::wstring& path, const std::string& content) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hFile, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
            CloseHandle(hFile);
        }
    }

    static std::string LoadFromCache(const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return "";

        DWORD size = GetFileSize(hFile, nullptr);
        if (size == 0 || size > 2 * 1024 * 1024) { // 2MB max
            CloseHandle(hFile);
            return "";
        }

        std::string buffer(size, '\0');
        DWORD read = 0;
        ReadFile(hFile, &buffer[0], size, &read, nullptr);
        CloseHandle(hFile);
        return buffer;
    }

    static std::string DownloadJson(const std::string& url) {
        HINTERNET hInternet = InternetOpenA("IceBreaker-OTA/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInternet) return "";

        // INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE
        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE;
        HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, flags, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            return "";
        }

        std::string response;
        char buffer[4096];
        DWORD bytesRead = 0;

        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            response.append(buffer, bytesRead);
        }

        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return response;
    }

    // Lightweight parser specifically for the OTA JSON schema:
    // "name": [ "pat1", "pat2" ]
    static std::unordered_map<std::string, std::vector<std::string>> ParsePatternsJson(const std::string& json) {
        std::unordered_map<std::string, std::vector<std::string>> result;

        size_t pos = 0;
        while (pos < json.size()) {
            size_t keyStart = json.find('"', pos);
            if (keyStart == std::string::npos) break;
            size_t keyEnd = json.find('"', keyStart + 1);
            if (keyEnd == std::string::npos) break;

            std::string key = json.substr(keyStart + 1, keyEnd - keyStart - 1);
            pos = keyEnd + 1;

            // Skip whitespace and find ':'
            while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) pos++;
            if (pos >= json.size() || json[pos] != ':') continue;
            pos++;

            // Skip whitespace after ':'
            while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) pos++;
            if (pos >= json.size()) break;

            // If the value is an array '['
            if (json[pos] == '[') {
                pos++;
                std::vector<std::string> patterns;
                while (pos < json.size() && json[pos] != ']') {
                    size_t strStart = json.find('"', pos);
                    if (strStart == std::string::npos) break;
                    size_t arrayEnd = json.find(']', pos);
                    if (arrayEnd != std::string::npos && strStart > arrayEnd) {
                        pos = arrayEnd;
                        break;
                    }
                    size_t strEnd = json.find('"', strStart + 1);
                    if (strEnd == std::string::npos) break;

                    patterns.push_back(json.substr(strStart + 1, strEnd - strStart - 1));
                    pos = strEnd + 1;
                    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n' || json[pos] == ',')) {
                        pos++;
                    }
                }
                if (pos < json.size() && json[pos] == ']') pos++;
                if (!patterns.empty()) {
                    result[key] = patterns;
                }
            }
        }

        return result;
    }
};

} // namespace IceBreaker
