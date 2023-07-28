#include <Windows.h>
#include <string>
#include <iostream>
#include "Helper.h"

// Declare the function pointer type
typedef HANDLE(WINAPI* OpenProcessFunc)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

int main() {
    std::cout << "Launching Seamless 2.0 with RoundtableHoldArena Mod..." << std::endl;

    HANDLE eldenring;
    HANDLE seamless = Helper::FindProcessByName(SEAMLESS_EXE);
    if (seamless == NULL) {
        bool result = Helper::StartProcess(SEAMLESS_EXE, "");

        if (!result) {
            MessageBox(NULL, "Couldn't launch Seamless 2.0. Make sure both seamless and this launcher are in the game folder.", "Error!", MB_ICONERROR | MB_OK);
            DebugLog(L"Couldn't start process.");
            return 0;
        }

        DebugLog(L"Waiting for real process to start...");
        eldenring = Helper::WaitForProcess(ELDENRING_EXE, WAIT_TIMEOUT);
        std::list<std::string> waitDlls = { SEAMLESS_DLL };
        Helper::WaitForDlls(eldenring, waitDlls);

        DWORD eldenringProcessId = GetProcessId(eldenring);
        if (Helper::IsProcessFullyInitialized(eldenringProcessId, WAIT_TIMEOUT)) {
            DebugLog("Injecting RoundtableHold.dll into process eldenring.exe.");
            TCHAR currentDir[MAX_PATH];
            if (GetCurrentDirectory(MAX_PATH, currentDir) <= 0) {
                DebugLog(L"Failed to get the current directory.");
                return 0;
            }
            Helper::InjectIntoProcess(eldenring, { std::string(currentDir) + ROUNDTABLE_DLL }, INJECTION_DELAY);
        }
    }
    return 0;
}



































//// Load the DLL
//HMODULE dllHandle = Helper::LoadDllFromSystemFolder("kernel32.dll");
//if (dllHandle == NULL) {
//    // Handle the error if the DLL fails to load
//    // Add error handling code here
//    return 1;
//}
//
//// Get the function address
//OpenProcessFunc pOpenProcess = reinterpret_cast<OpenProcessFunc>(GetProcAddress(dllHandle, "OpenProcess"));
//if (pOpenProcess == NULL) {
//    // Handle the error if the function is not found in the DLL
//    // Add error handling code here
//    FreeLibrary(dllHandle);
//    return 1;
//}
//
//// Now you can call the function using the function pointer
//// For example:
//DWORD desiredAccess = PROCESS_ALL_ACCESS;
//BOOL inheritHandle = FALSE;
//DWORD processId = 12345;
//HANDLE processHandle = pOpenProcess(desiredAccess, inheritHandle, processId);
//
//// Remember to free the library when you're done using it
//FreeLibrary(dllHandle);
//
//// Add your logic here using the processHandle returned by the OpenProcess function
//// ...