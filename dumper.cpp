#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <Psapi.h>
#include <Tlhelp32.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "xor.hpp"

uint32_t get_process_id(const wchar_t* name) {
    auto h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!h_snapshot || h_snapshot == INVALID_HANDLE_VALUE) return -1;

    auto pe32 = PROCESSENTRY32W{ sizeof PROCESSENTRY32W };
    if (Process32FirstW(h_snapshot, &pe32)) {
        do {
            if (!std::wcscmp(pe32.szExeFile, name)) {
                CloseHandle(h_snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(h_snapshot, &pe32));
    }

    CloseHandle(h_snapshot); return -1;
}

int main() {
    HANDLE h_process = nullptr;

    auto cleanup = [&]() {
        if (h_process && h_process != INVALID_HANDLE_VALUE) 
            CloseHandle(h_process);
        };

    std::vector<std::pair<void*, SIZE_T>> vec_allocations_before_injection, vec_allocations_after_injection;

    try {
        SetConsoleTitleA(_("Process memory dumper by hollow979"));

        std::cout << _("[INFO] Enter the target process name: ");
        std::wstring process_name; std::wcin >> process_name;

        auto pid = get_process_id(process_name.c_str());
        if (pid == UINT_MAX)
            throw std::runtime_error(_("The target process isn't open!"));

        h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if (!h_process || h_process == INVALID_HANDLE_VALUE)
            throw std::runtime_error(_("Failed to open a handle to the target process!"));

        SYSTEM_INFO si; GetSystemInfo(&si);

        void* mem = nullptr;
        MEMORY_BASIC_INFORMATION mbi;
        std::memset(&mbi, 0, sizeof mbi);

        while (mem < si.lpMaximumApplicationAddress) {
            (VirtualQueryEx)(h_process, mem, &mbi, sizeof mbi);

            std::printf(_("[SCANNER] Allocation Base: 0x%p Region Size: 0x%X\n"), mbi.BaseAddress, mbi.RegionSize);
            vec_allocations_before_injection.push_back({ mbi.BaseAddress, mbi.RegionSize });

            mem = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
        }

        std::cout << _("[SCANNER FINISHED] Allocation count before injection: ") << vec_allocations_before_injection.size() << "\n";
        std::cout << _("[INFO] Inject and press delete to scan for and dump the new allocations!\n");

        while (!GetAsyncKeyState(VK_DELETE))
            Sleep(100);

        mem = nullptr;
        std::memset(&mbi, 0, sizeof mbi);

        std::cout << _("[SCANNER] Started scan!\n");

        while (mem < si.lpMaximumApplicationAddress) {
            (VirtualQueryEx)(h_process, mem, &mbi, sizeof mbi);

            bool unique = true;
            for (const auto& a : vec_allocations_before_injection) {
                if (a.first == mbi.BaseAddress) {
                    unique = false;
                    break;
                }
            }

            if (unique && mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                wchar_t buf[MAX_PATH];
                if ((K32GetMappedFileNameW)(h_process, mbi.BaseAddress, buf, MAX_PATH)) {

                    mem = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
                    continue;
                }

                vec_allocations_after_injection.push_back({ mbi.BaseAddress, mbi.RegionSize });
            }
            mem = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
        }

        if (vec_allocations_after_injection.empty())
            throw std::runtime_error(_("No new allocations found!"));

        auto directory_path = std::filesystem::current_path().wstring() + L"\\" + process_name;
        if (!CreateDirectoryW(directory_path.c_str(), 0) && GetLastError() == ERROR_PATH_NOT_FOUND) 
            throw std::runtime_error(_("CreateDirectoryW failed! (0)"));

        auto dump_path = directory_path + L"\\" + std::to_wstring(pid);
        if (!CreateDirectoryW(dump_path.c_str(), 0))
            throw std::runtime_error(_("CreateDirectoryW failed! (1)"));

        auto dump_file_path = dump_path + L"\\" + std::to_wstring(pid) + L".bin";
        auto h_dump_file = CreateFileW(dump_file_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, 2, FILE_ATTRIBUTE_NORMAL, 0);
        if (!h_dump_file || h_dump_file == INVALID_HANDLE_VALUE) 
            throw std::runtime_error(_("CreateFileW failed!"));

        for (const auto& a : vec_allocations_after_injection) {
            std::printf(_("[SCANNER] Allocation Base: 0x%p Region Size: 0x%X\n"), a.first, a.second);

            auto buf = std::malloc(a.second);
            if (!buf)
                throw std::runtime_error(_("Failed to allocate buffer for reading memory!"));

            SIZE_T nr_of_bytes_read = 0;
            if (!(ReadProcessMemory)(h_process, a.first, buf, a.second, &nr_of_bytes_read)) {
                std::string errorMsg = _("RPM failed! Error code: ") + std::to_string(GetLastError());
                throw std::runtime_error(errorMsg);
            }

            std::cout << _("[SCANNER] Number of bytes read: ") << nr_of_bytes_read << "\n";

            if (!(WriteFile)(h_dump_file, buf, nr_of_bytes_read, 0, 0))
                throw std::runtime_error(_("WriteFile failed!"));

            std::free(buf);
        }

        std::cout << _("[SCANNER FINISHED] New allocations after injection: ") << vec_allocations_after_injection.size();

        CloseHandle(h_dump_file);
        cleanup();
        std::cout << _("[SUCCESS] The dump can be found in the same folder as the dumper itself. \nTool made by hollow979.\n");
        system(_("PAUSE"));
    }
    catch (const std::runtime_error& err) {
        cleanup();
        MessageBoxA(0, err.what(), _("Error!"), MB_OK | MB_ICONERROR);
        return 1;
    }

    return 0;
}