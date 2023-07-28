#pragma once
#include <Windows.h>
#include <string>
#include <tlhelp32.h>
#include <chrono>
#include <Shlwapi.h>
#include <unordered_map>
#include <psapi.h>


#ifdef DEBUG
#define DebugLog(msg) std::wcout << msg << std::endl
#else
#define DebugLog(msg)
#endif

#define INJECTION_DELAY 5000
#define WAIT_TIMEOUT 30000

#define ELDENRING_EXE "eldenring.exe"
#define SEAMLESS_EXE "launch_elden_ring_seamlesscoop.exe"

#define SEAMLESS_DLL "elden_ring_seamless_coop.dll"
#define ROUNDTABLE_DLL "\\mods\\RoundtableHoldArena\\RoundTableHoldArena.dll"

namespace Helper {
    // Function to convert string to wide string
    std::wstring ToWideString(const std::string& str) {
        std::wstring wstr(str.begin(), str.end());
        return wstr;
    }

    // Function to find a process by name
    HANDLE FindProcessByName(const std::string& processName) {
        HANDLE hProcessSnap;
        PROCESSENTRY32 pe32;
        HANDLE hProcess = NULL;

        // Take a snapshot of all processes in the system
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            return NULL;
        }

        // Set the size of the structure before using it.
        pe32.dwSize = sizeof(PROCESSENTRY32);

        // Walk the process list to find the process by name
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                // Compare process names (case-insensitive)
                if (_stricmp(pe32.szExeFile, processName.c_str()) == 0) {
                    // Found a matching process, open it for desired access
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                    break;
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }

        // Close the snapshot handle
        CloseHandle(hProcessSnap);

        return hProcess;
    }

    HMODULE LoadDllFromSystemFolder(std::string dllName)
    {
        std::string systemFolderPath = "";
        char dummy[1];
        UINT pathLength = GetSystemDirectoryA(dummy, 1);
        systemFolderPath.resize(pathLength);
        LPSTR lpSystemFolderPath = const_cast<char*>(systemFolderPath.c_str());
        GetSystemDirectoryA(lpSystemFolderPath, systemFolderPath.size());
        systemFolderPath = lpSystemFolderPath;

        HMODULE dll = LoadLibraryA(std::string(systemFolderPath + "\\" + dllName).c_str());
        return dll;
    }

    // Function to start a new process
    bool StartProcess(const std::string& applicationName, const std::string& commandLine = "") {
        STARTUPINFO startupInfo = {};
        PROCESS_INFORMATION processInfo = {};

        // Fill in the startup information (optional)
        startupInfo.cb = sizeof(STARTUPINFO);

        // Convert the string parameters to LPCTSTR (const char*) pointers
        LPCTSTR lpApplicationName = applicationName.c_str();
        LPSTR lpCommandLine = (commandLine.empty()) ? nullptr : const_cast<LPSTR>(commandLine.c_str());

        // Create the process
        if (!CreateProcess(
            lpApplicationName,
            lpCommandLine,
            NULL,               // Process attributes (default NULL)
            NULL,               // Thread attributes (default NULL)
            FALSE,              // Inherit handles (FALSE = don't inherit)
            0,                  // Creation flags (default 0)
            NULL,               // Environment (default NULL)
            NULL,               // Current directory (default NULL)
            &startupInfo,
            &processInfo
        )) {
            // Handle the error if the process creation fails
            // Add error handling code here
            return false;
        }

        // Close handles to avoid resource leaks
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);

        return true;
    }

    // Function to wait for a process to appear
    HANDLE WaitForProcess(const std::string& name, uint32_t timeout) {
        HANDLE process = nullptr;
        int timeoutCounter = static_cast<int>(timeout);
        int pollingRate = 500;

        // Logging is not directly available in C++, so you can output to console for now
        // To use proper logging, you can integrate a logging library like spdlog.

        DebugLog(L"Waiting for process '" + ToWideString(name) + L"'");

        while (timeoutCounter > 0) {
            process = FindProcessByName(name);
            if (process != nullptr) {
                DebugLog(L"Process found!");
                break;
            }

            timeoutCounter -= pollingRate;
            std::this_thread::sleep_for(std::chrono::milliseconds(pollingRate));
        }

        if (process == nullptr) {
            DebugLog(L"Timed out waiting for process '" + ToWideString(name) + L"'");
            // You can handle the error further here, if needed.
        }

        return process;
    }

    // Function to convert string to lowercase
    std::string ToLower(const std::string& str) {
        std::string result = str;
        for (char& c : result) {
            c = std::tolower(c);
        }
        return result;
    }

    // Function to extract the filename from a given path
    std::string GetFileName(const std::string& fullPath) {
        // Find the position of the last directory separator
        size_t lastSlashPos = fullPath.find_last_of("\\/");
        if (lastSlashPos != std::string::npos) {
            // Return the substring after the last separator (the filename)
            return fullPath.substr(lastSlashPos + 1);
        }

        // If no separator is found, return the full path as the filename
        return fullPath;
    }

    // Function to wait for DLLs to be loaded in the process
    void WaitForDlls(HANDLE processHandle, std::list<std::string>& waitDlls, uint32_t timeout = WAIT_TIMEOUT) {
        std::unordered_map<std::string, std::vector<std::string>> loadedModules;

        int timeoutCounter = static_cast<int>(timeout);
        int pollingRate = 100;

        DebugLog(L"Waiting for DLLs to be loaded in the process...");

        while (timeoutCounter > 0) {
            // Wait for the process to be idle (optional)
            if (WaitForInputIdle(processHandle, WAIT_TIMEOUT) == WAIT_TIMEOUT) {
                DebugLog(L"Timed out waiting for process to be idle.");
                break;
            }

            bool modulesChanged = false;
            HMODULE hModules[1024];
            DWORD needed;

            // Enumerate process modules to check for DLLs
            if (EnumProcessModules(processHandle, hModules, sizeof(hModules), &needed)) {
                int numModules = needed / sizeof(HMODULE);
                for (int i = 0; i < numModules; ++i) {
                    char moduleFileName[MAX_PATH];
                    if (GetModuleFileNameExA(processHandle, hModules[i], moduleFileName, MAX_PATH)) {
                        std::string moduleName = ToLower(moduleFileName);

                        // Trim the path so only filename and extension are left
                        std::string trimmedModuleName = GetFileName(moduleFileName);

                        if (!loadedModules.count(trimmedModuleName)) {
                            // Module was loaded for the first time
                            DebugLog(L"Loaded " + ToWideString(trimmedModuleName));
                            loadedModules[trimmedModuleName] = std::vector<std::string>{ moduleFileName };
                            modulesChanged = true;
                        }
                        else if (std::find(loadedModules[trimmedModuleName].begin(), loadedModules[trimmedModuleName].end(), moduleFileName) == loadedModules[trimmedModuleName].end()) {
                            // Module has changed (reloaded)
                            DebugLog(L"Changed " + ToWideString(trimmedModuleName));
                            loadedModules[trimmedModuleName].push_back(moduleFileName);
                            modulesChanged = true;
                        }

                        // Check if the loaded module matches any of the wait DLLs
                        waitDlls.remove_if([trimmedModuleName](const std::string& waitDll) {
                            return trimmedModuleName == ToLower(waitDll);
                        });
                    }
                }
            }

            if (modulesChanged) {
                DebugLog(L"Timeout reset since modules changed");
                timeoutCounter = static_cast<int>(timeout);
            }

            timeoutCounter -= pollingRate;
            DebugLog(L"Timing out in: " + std::to_wstring(timeoutCounter));
            std::this_thread::sleep_for(std::chrono::milliseconds(pollingRate));
            if (waitDlls.empty()) break;
        }

        if (!waitDlls.empty()) {
            DebugLog(L"Not all wait DLLs found. Continuing with injection. See log for details");
            for (const std::string& waitDll : waitDlls) {
                DebugLog(L"Wait DLL not found: " + ToWideString(waitDll));
            }
        }
        else {
            DebugLog(L"Process modules possibly fully loaded");
        }
    }

    // Function to inject a list of DLLs into a process
    void InjectIntoProcess(HANDLE processHandle, const std::vector<std::string>& dlls, uint32_t delay = INJECTION_DELAY) {

        DWORD processId = GetProcessId(processHandle);
        HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

        DebugLog(L"Injecting DLLs into the process...");

        HMODULE kernel32 = LoadDllFromSystemFolder("kernel32.dll");
        FARPROC loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
        if (loadLibraryAddr == nullptr) {
            DebugLog(L"Error: Failed to retrieve the address for LoadLibraryA");
            return;
        }

        int dllIndex = 1;
        for (const std::string& dll : dlls) {
            DebugLog(L"----------------------------------------------");
            DebugLog(L"Delaying next DLL injection by " + std::to_wstring(delay) + L" ms");
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));

            DebugLog(L"----------------------------------------------");
            DebugLog(L"Attempting to inject DLL, " + std::to_wstring(dllIndex) + L" of " + std::to_wstring(dlls.size()) + L", " + ToWideString(dll) + L"...");

            // Allocate memory in the process to write the DLL path
            SIZE_T size = (dll.size() + 1) * sizeof(char);
            LPVOID allocMemAddress = VirtualAllocEx(procHandle, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (allocMemAddress == nullptr) {
                DebugLog(L"Error: Failed to allocate memory in the process");
                return;
            }

            // Write the DLL path into the process memory
            if (!WriteProcessMemory(procHandle, allocMemAddress, dll.c_str(), size, nullptr)) {
                DebugLog(L"Error: Failed to write the DLL path into the memory of the process");
                VirtualFreeEx(procHandle, allocMemAddress, 0, MEM_RELEASE);
                return;
            }

            // Create a remote thread to load the DLL
            HANDLE threadHandle = CreateRemoteThread(procHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocMemAddress, 0, nullptr);
            if (threadHandle == nullptr) {
                DebugLog(L"Error: Failed to create a remote thread in the process");
                VirtualFreeEx(procHandle, allocMemAddress, 0, MEM_RELEASE);
                return;
            }

            // Wait for the DLL to load
            WaitForSingleObject(threadHandle, INFINITE);

            // Clean up resources
            CloseHandle(threadHandle);
            VirtualFreeEx(procHandle, allocMemAddress, 0, MEM_RELEASE);

            DebugLog(L"Injected!");
            dllIndex++;
        }

        DebugLog(L"----------------------------------------------");
        DebugLog(L"DLL injection completed.");
    }
    
    
    // Function to check if a window is responding
    bool IsWindowResponding(HWND hwnd) {
        DWORD dwProcessId;
        DWORD dwThreadId = GetWindowThreadProcessId(hwnd, &dwProcessId);
        HWINSTA hwinsta = GetProcessWindowStation();
        HWINSTA hwinstaUser = OpenWindowStation("WinSta0", FALSE, MAXIMUM_ALLOWED);
        SetProcessWindowStation(hwinstaUser);
        bool responding = IsHungAppWindow(hwnd) == FALSE;
        SetProcessWindowStation(hwinsta);
        CloseWindowStation(hwinstaUser);
        return responding;
    }

    // Function to wait for the process to be fully initialized
    bool IsProcessFullyInitialized(DWORD processId, DWORD timeoutMillis) {
        DWORD startTime = GetTickCount();
        bool fullyInitialized = false;

        DebugLog(L"Waiting for the process to be fully initialized...");

        while (!fullyInitialized) {
            HWND hwnd = FindWindowEx(nullptr, nullptr, nullptr, nullptr);
            while (hwnd) {
                DWORD wndProcessId = 0;
                GetWindowThreadProcessId(hwnd, &wndProcessId);
                if (wndProcessId == processId) {
                    // Check if the window is responsive (fully initialized)
                    if (IsWindowResponding(hwnd)) {
                        fullyInitialized = true;
                        break;
                    }
                }
                hwnd = FindWindowEx(nullptr, hwnd, nullptr, nullptr);
            }

            if (fullyInitialized)
                break;

            DWORD elapsedTime = GetTickCount() - startTime;
            if (elapsedTime >= timeoutMillis)
                break;

            // Wait a short period before checking again (adjust the interval as needed)
            Sleep(100);
        }

        if (fullyInitialized) {
            DebugLog(L"Process is fully initialized.");
        }
        else {
            DebugLog(L"Process is not fully initialized within the specified timeout.");
        }

        return fullyInitialized;
    }
};