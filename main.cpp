#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <stdio.h>

DWORD GetPidByName (const char *name)
{
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        return 0;
    }

    while (Process32Next(hSnapshot, &pe32))
    {
        if (!stricmp(name, pe32.szExeFile))
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hSnapshot);

    return pid;
}

HANDLE GetHandleFromPid (DWORD pid)
{
    HANDLE hProc;

    while ((hProc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid)) == INVALID_HANDLE_VALUE) {
        Sleep(1);
    }

    return hProc;
}

HANDLE GetHandleFromName (const char *name)
{
    return GetHandleFromPid(GetPidByName(name));
}

int main (int argc, char **argv)
{
    HANDLE hNier = GetHandleFromName ("NieRAutomata.exe");

    // Check patch state
    // Thanks to @Wunkolo (https://twitter.com/Wunkolo/status/843387447656435712)
    LPVOID address = (void *) 0x1413FC410;
    std::uint64_t data;
    SIZE_T bytes_read;

    if (!(ReadProcessMemory (hNier, address, (void *) &data, sizeof(data), &bytes_read))) {
        printf ("Cannot read process memory.");
        return -1;
    }

    std::uint64_t new_data;
    switch (data) {
        case 0:
            // Unpatched
            MessageBox(NULL, "Free camera is enabled!", "NieR:Automata", 0);
            new_data = 0x80000000;
        break;

        default:
            MessageBox(NULL, "Free camera is disabled!", "NieR:Automata", 0);
            // Patch, back to normal
            new_data = 0;
        break;
    }

    if (!(WriteProcessMemory (hNier, address, (void *) &new_data, sizeof(new_data), &bytes_read))) {
        printf ("Cannot write process memory.");
        return -1;
    }

    return 0;
}