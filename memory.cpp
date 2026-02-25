/*
* Memory Hacking Library C++
* by Daniil Nabiulin
* version 1.0.3
* https://github.com/kirizaku/memory

Licensed under the MIT License <http://opensource.org/licenses/MIT>.

Copyright (c) 2022-2026 Daniil Nabiulin <https://github.com/kirizaku>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "memory.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>
#include <vector>

#if defined(__linux__)
#include <dirent.h>
#include <dlfcn.h>

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#endif

#define LOG_ERROR(msg) do { \
    std::cerr << "[ERROR] " << msg << " (errno: " << errno << ")" << std::endl; \
} while(0)

#if defined(__linux__)
void* mem::inject_syscall(mem_pid_t pid, int syscall_id, void* arg0, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5)
{
    void* result = 0;
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        LOG_ERROR("Failed to attach to process");
        return result;
    }

    int status;
    wait(&status);

    if (!WIFSTOPPED(status)) {
        LOG_ERROR("Process not stopped after attach");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    struct user_regs_struct regs, regs_backup;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs_backup) == -1) {
        LOG_ERROR("Failed to get registers");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    void* code_addr;
    regs = regs_backup;
    #if defined(__x86_64__)
    regs.rax = (uintptr_t)syscall_id;
    regs.rdi = (uintptr_t)arg0;
    regs.rsi = (uintptr_t)arg1;
    regs.rdx = (uintptr_t)arg2;
    regs.r10 = (uintptr_t)arg3;
    regs.r8  = (uintptr_t)arg4;
    regs.r9  = (uintptr_t)arg5;

    code_addr = (void*)regs.rip;
    #else
    regs.eax = (uintptr_t)syscall_id;
    regs.ebx = (uintptr_t)arg0;
    regs.ecx = (uintptr_t)arg1;
    regs.edx = (uintptr_t)arg2;
    regs.esi = (uintptr_t)arg3;
    regs.edi = (uintptr_t)arg4;
    regs.ebp = (uintptr_t)arg5;

    code_addr = (void*)regs.eip;
    #endif

    const uint8_t syscall_buffer[] = {
    #if defined(__x86_64__)
    0x0F,0x05
    #else
    0xcd,0x80
    #endif
    }; //Fast System Call

    uintptr_t injection_syscall;
    std::memcpy(&injection_syscall, syscall_buffer, sizeof(injection_syscall));

    uintptr_t original_code = ptrace(PTRACE_PEEKTEXT, pid, (void*)code_addr, 0);
    if (original_code == -1) {
        LOG_ERROR("Failed to peek text");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    if (ptrace(PTRACE_POKETEXT, pid, (void*)code_addr, (void*)injection_syscall) == -1) {
        LOG_ERROR("Failed to poke text");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        LOG_ERROR("Failed to set registers");
        ptrace(PTRACE_POKETEXT, pid, (void*)code_addr, (void*)original_code);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
        LOG_ERROR("Failed to single step");
        ptrace(PTRACE_POKETEXT, pid, (void*)code_addr, (void*)original_code);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    waitpid(pid, &status, WSTOPPED);

    if (!WIFSTOPPED(status)) {
        LOG_ERROR("Process not stopped after single step");
    }

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        LOG_ERROR("Failed to get registers after execution");
    }

    #if defined(__x86_64__)
    result = (void*)regs.rax;
    #else
    result = (void*)regs.eax;
    #endif

    if (ptrace(PTRACE_POKETEXT, pid, (void*)code_addr, original_code) == -1) {
        LOG_ERROR("Failed to restore original code");
    }

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs_backup) == -1) {
        LOG_ERROR("Failed to restore registers");
    }

    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
        LOG_ERROR("Failed to detach from process");
    }

    return result;
}

void* mem::inject_call_function(mem_pid_t pid, void* code_addr, void* dlopen_addr, void* arg0, void* arg1)
{
    void* result = 0;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        LOG_ERROR("Failed to attach to process");
        return result;
    }

    int status;
    wait(&status);

    if (!WIFSTOPPED(status)) {
        LOG_ERROR("Process not stopped after attach");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    struct user_regs_struct regs, regs_backup;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs_backup) == -1) {
        LOG_ERROR("Failed to get registers");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    #if defined(__x86_64__)
    regs = regs_backup;
    regs.rip = (uintptr_t)code_addr;
    regs.rsp -= (regs.rsp) % 16;
    regs.rbp = regs.rsp - 8;
    regs.rax = (uintptr_t)dlopen_addr;
    regs.rsi = (uintptr_t)arg1;
    regs.rdi = (uintptr_t)arg0;
    #else
    regs = regs_backup;
    regs.esp -= (regs.esp % 16);
    regs.esp -= 4;
    regs.eip = (uintptr_t)code_addr;
    regs.eax = (uintptr_t)dlopen_addr;
    regs.esp -= 4;
    ptrace(PTRACE_POKEDATA, pid, (void*)regs.esp, (void*)arg1);
    regs.esp -= 4;
    ptrace(PTRACE_POKEDATA, pid, (void*)regs.esp, arg0);
    #endif

    const uint8_t call_function_buffer[] = {
    0xff,0xd0, 0xcc
    }; // Call Function

    uintptr_t original_code = ptrace(PTRACE_PEEKTEXT, pid, (void*)code_addr, 0);
    if (original_code == -1) {
        LOG_ERROR("Failed to peek text");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        LOG_ERROR("Failed to set registers");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    uintptr_t injection_callfunc;
    std::memcpy(&injection_callfunc, call_function_buffer, sizeof(injection_callfunc));
    if (ptrace(PTRACE_POKETEXT, pid, (void*)code_addr, (void*)injection_callfunc) == -1) {
        LOG_ERROR("Failed to inject call function");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        LOG_ERROR("Failed to continue process");
        ptrace(PTRACE_POKETEXT, pid, (void*)code_addr, original_code);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return result;
    }

    waitpid(pid, &status, WSTOPPED);

    if (!WIFSTOPPED(status)) {
        LOG_ERROR("Process not stopped after execution");
    }

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        LOG_ERROR("Failed to get registers after execution");
    }

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs_backup) == -1) {
        LOG_ERROR("Failed to restore registers");
    }

    #if defined(__x86_64__)
    result = (void*)regs.rax;
    #else
    result = (void*)regs.eax;
    #endif

    if (ptrace(PTRACE_POKETEXT, pid, (void*)code_addr, (void*)original_code) == -1) {
        LOG_ERROR("Failed to restore original code");
    }

    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
        LOG_ERROR("Failed to detach from process");
    }

    return result;
}

uintptr_t mem::get_dlopen_address()
{
    void* handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!handle) {
        LOG_ERROR("Failed to open libc");
        return 0;
    }

    dlerror();

    void* dlopen_addr = dlsym(handle, "dlopen");
    const char* error = dlerror();

    if (error) {
        LOG_ERROR("Failed to find dlopen");
        dlclose(handle);
        return 0;
    }

    Dl_info info;
    if (dladdr(dlopen_addr, &info)) {
        uintptr_t base_addr = (uintptr_t)info.dli_fbase;
        uintptr_t offset = (uintptr_t)dlopen_addr - base_addr;

        dlclose(handle);
        return offset;
    }

    dlclose(handle);
    return 0;
}

#endif

mem::mem_pid_t mem::get_pid(string_t process_name) {
    mem_pid_t pid = 0;
    #if defined(_WIN32)
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 process_entry;
        process_entry.dwSize = sizeof(process_entry);

        if (Process32First(hSnap, &process_entry)) {
            do {
                if (!mem_cmp(process_entry.szExeFile, process_name.c_str())) {
                    pid = process_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &process_entry));
        }
    }
    CloseHandle(hSnap);
    #else
    DIR* dir = opendir("/proc");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            int id = atoi(entry->d_name);
            if (id > 0) {
                std::string comm_path = "/proc/" + std::string(entry->d_name) + "/comm";
                std::ifstream comm_file(comm_path);
                if (!comm_file) {
                    continue;
                }

                std::string comm;
                std::getline(comm_file, comm);
                comm_file.close();

                if (comm == process_name) {
                    pid = id;
                    break;
                }
            }
        } closedir(dir);
    }
    #endif
    return pid;
}

mem::string_t mem::get_process_name(mem_pid_t pid) {
    string_t process_name;
    #if defined(_WIN32)
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 process_entry;
        process_entry.dwSize = sizeof(process_entry);

        if (Process32First(hSnap, &process_entry)) {
            do {
                if (pid == process_entry.th32ProcessID) {
                    process_name = string_t(process_entry.szExeFile);
                    break;
                }
            } while (Process32Next(hSnap, &process_entry));
        }
    }
    CloseHandle(hSnap);
    #else
    std::stringstream comm_file_stream;
    comm_file_stream << "/proc/" << pid << "/comm";
    std::ifstream comm_file(comm_file_stream.str());

    if (comm_file.is_open()) {
        std::getline(comm_file, process_name);
    }
    comm_file.close();
    #endif
    return process_name;
}

uintptr_t mem::get_module(mem_pid_t pid, string_t module_name) {
    uintptr_t module_base = 0;
    #if defined(_WIN32)
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 module_entry;
        module_entry.dwSize = sizeof(module_entry);
        if (Module32First(hSnap, &module_entry)) {
            do {
                if (!mem_cmp(module_entry.szModule, module_name.c_str()) || !mem_cmp(module_entry.szExePath, module_name.c_str())) {
                    module_base = (uintptr_t)module_entry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &module_entry));
        }
    }
    CloseHandle(hSnap);
    #else
    std::stringstream maps_file;
    maps_file << "/proc/" << pid << "/maps";
    std::ifstream maps_ifst(maps_file.str());

    if(!maps_ifst.is_open()) return module_base;

    maps_file.str(std::string());
    maps_file << maps_ifst.rdbuf();

    size_t module_base_path = maps_file.str().find(module_name);
    size_t module_base_start = maps_file.str().rfind('\n', module_base_path);
    if (module_base_start == maps_file.str().npos) { module_base_start = 0; }

    size_t module_base_end = maps_file.str().find('-', module_base_path);
    if(module_base_end == maps_file.str().npos) return module_base;

    module_base = std::stoul(maps_file.str().substr(module_base_start, module_base_end - module_base_start), nullptr, 16);
    maps_ifst.close();
    #endif
    return module_base;
}

uintptr_t mem::load_module(mem_pid_t pid, string_t path) {
    uintptr_t module_base = 0;
    #if defined(_WIN32)
    size_t path_size = mem_len(path.c_str()) + 1;
    void* path_address = allocate(pid, 0, path_size, PAGE_EXECUTE_READWRITE);
    if (path_address == 0) return module_base;
    write(pid, path_address, (LPCVOID*)path.c_str(), path_size);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        HANDLE hThread = (HANDLE)CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, path_address, 0, 0);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        CloseHandle(hProcess);
    }
    deallocate(pid, path_address, path_size);
    #else
    uintptr_t glibc_module = mem::get_module(pid, "libc.so.6");
    uintptr_t dlopen_offset = mem::get_dlopen_address();
    uintptr_t dlopen_addr = glibc_module + dlopen_offset;

    size_t path_size = mem_len(path.c_str()) + 1;
    size_t text_size = sysconf(_SC_PAGESIZE);
    size_t stack_size = 2 * 1024 * 1024;

    void* path_address = allocate(pid, 0, text_size + stack_size, protection::READ_WRITE_EXECUTE);
    mem::write(pid, path_address, (void*)path.c_str(), path_size);

    void* code_addr = (void*)((uintptr_t)path_address + path_size);
    inject_call_function(pid, (void*)code_addr, (void*)dlopen_addr, path_address, (void*)RTLD_LAZY);

    mem::deallocate(pid, path_address, text_size + stack_size);

    #endif
    module_base = get_module(pid, path);
    return module_base;
}

void* mem::allocate(mem_pid_t pid, void* src, size_t size, uintptr_t protection) {
    void* result = 0;
    #if defined(_WIN32)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
    result = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, protection);
    if (!result) result = FALSE;
    CloseHandle(hProcess);
    #else
    int syscall_id = 0;
    #if defined(__x86_64__)
    syscall_id = __NR_mmap;
    #else
    syscall_id = __NR_mmap2;
    #endif

    result = inject_syscall(pid, syscall_id, 0, (void*)size, (void*)protection, (void*)(MAP_PRIVATE | MAP_ANON), 0, 0);
    if (result == ((void *)syscall_id) || result == MAP_FAILED) result = 0;
    #endif
    return result;
}

bool mem::deallocate(mem_pid_t pid, void* src, size_t size) {
    bool result = 0;
    #if defined(_WIN32)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
    result = VirtualFreeEx(hProcess, src, 0, MEM_RELEASE) != 0 ? true : false;
    CloseHandle(hProcess);
    #else
    result = inject_syscall(pid, __NR_munmap, src, (void*)size, 0, 0, 0, 0) == 0 ? true : false;
    #endif
    return result;
}

bool mem::protect(mem_pid_t pid, void* src, size_t size, uintptr_t protection, uintptr_t *old_protection) {
    bool result = 0;
    #if defined(_WIN32)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD old_protect = 0;
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
    result = VirtualProtectEx(hProcess, src, size, protection, &old_protect) != 0 ? true : false;
    if (old_protection) *old_protection = old_protect;
    CloseHandle(hProcess);
    #else
    if (old_protection) {
    std::stringstream maps_file;
    maps_file << "/proc/" << pid << "/maps";
    std::ifstream maps_ifst(maps_file.str());

    if(!maps_ifst.is_open()) return result;

    maps_file.str(std::string());
    maps_file << maps_ifst.rdbuf();

    std::stringstream strm;
    strm << src;
    std::string addr = strm.str();
    addr.erase(addr.find("0x"), 2);
    addr = addr + "-";

    size_t addr_protection_path = maps_file.str().find(addr);
    if (addr_protection_path == maps_file.str().npos) { *old_protection = 0; return result; }

    size_t addr_protection_start = maps_file.str().find(' ', addr_protection_path);
    if (addr_protection_start == maps_file.str().npos) { *old_protection = 0; return result; }

    size_t end = addr_protection_start + 4;

    intptr_t prot = 0;
    for(size_t i = addr_protection_start; i < end; i++)
    {
        char c = maps_file.str()[i];
        switch(c) {
            case 'r': 	prot |= PROT_READ;		break;
            case 'w':	prot |= PROT_WRITE;		break;
            case 'x':	prot |= PROT_EXEC; 		break;
        }
    }
    *old_protection = prot;
    maps_ifst.close();
    }
    result = inject_syscall(pid, __NR_mprotect, src, (void*)size, (void*)protection, 0, 0, 0) == 0 ? true : false;
    #endif
    return result;
}

bool mem::query(mem_pid_t pid, void* src, memory_information *mi)
{
    bool result = 0;
    #if defined(_WIN32)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;

    MEMORY_BASIC_INFORMATION mbi;
    result = (size_t)VirtualQueryEx(hProcess, (LPCVOID)src, &mbi, sizeof(mbi)) != 0 ? true : false;
    if (result) {
        mi->base_address		= mbi.BaseAddress;
        mi->allocation_base		= mbi.AllocationBase;
        mi->allocation_protect	= mbi.AllocationProtect;
        #if defined(_WIN64)
        mi->partition_id		= mbi.PartitionId;
        #endif
        mi->size				= mbi.RegionSize;
        mi->state				= mbi.State;
        mi->protect				= mbi.Protect;
        mi->type				= mbi.Type;
    }
    CloseHandle(hProcess);
    #else
    std::ifstream maps_ifs("/proc/" + std::to_string(pid) + "/maps");
    std::string line;

    if (!maps_ifs.is_open())
        return result;

    uintptr_t address = reinterpret_cast<uintptr_t>(src);
    while (std::getline(maps_ifs, line)) {
        std::istringstream iss(line);
        std::string range, permissions;
        uintptr_t start, end;

        iss >> range >> permissions;
        size_t pos = range.find('-');

        if (pos != std::string::npos) {
            start = std::stoul(range.substr(0, pos), nullptr, 16);
            end = std::stoul(range.substr(pos + 1), nullptr, 16);

            if (address >= start && address < end) {
                mi->base_address = reinterpret_cast<void*>(start);
                mi->size = end - start;

                int prot = 0;
                if (permissions.find('r') != std::string::npos) prot |= PROT_READ;
                if (permissions.find('w') != std::string::npos) prot |= PROT_WRITE;
                if (permissions.find('x') != std::string::npos) prot |= PROT_EXEC;
                mi->protect = prot;
                mi->type = (permissions.find('p') != std::string::npos) ? MAP_PRIVATE : MAP_SHARED;

                if (std::getline(maps_ifs, line)) {
                    std::istringstream next_iss(line);
                    std::string next_range;
                    uintptr_t next_start;
                    next_iss >> next_range >> permissions;

                    size_t next_pos = next_range.find('-');
                    if (next_pos != std::string::npos) {
                        next_start = std::stoul(next_range.substr(0, next_pos), nullptr, 16);
                        mi->next_address = reinterpret_cast<void*>(next_start);
                    }
                } else { mi->next_address = 0; }

                result = true;
                break;
            }
        }
    }
    #endif
    return result;
}

bool mem::read(mem_pid_t pid, void* src, void* dst, size_t size) {
    bool result = 0;
    #if defined(_WIN32)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
    result = ReadProcessMemory(hProcess, (LPCVOID)src, dst, size, 0) != 0 ? true : false;
    CloseHandle(hProcess);
    #else
    struct iovec iosrc;
    struct iovec iodst;
    iodst.iov_base = dst;
    iodst.iov_len  = size;
    iosrc.iov_base = src;
    iosrc.iov_len  = size;
    result = (size_t)process_vm_readv(pid, &iodst, 1, &iosrc, 1, 0) == size ? true : false;
    #endif
    return result;
}

bool mem::write(mem_pid_t pid, void* src, void* dst, size_t size) {
    bool result = 0;
    #if defined(_WIN32)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
    result = WriteProcessMemory(hProcess, src, (LPCVOID)dst, size, 0) != 0 ? true : false;
    CloseHandle(hProcess);
    #else
    struct iovec iosrc;
    struct iovec iodst;
    iosrc.iov_base = src;
    iosrc.iov_len = size;
    iodst.iov_base = dst;
    iodst.iov_len = size;
    result = (size_t)process_vm_writev(pid, &iodst, 1, &iosrc, 1, 0) == size ? true : false;
    #endif
    return result;
}

bool mem::nop_ex(mem_pid_t pid, void* src, size_t size) {
    bool result = 0;
    std::vector<uint8_t> nop;
    nop.resize(size);
    std::fill(nop.begin(), nop.end(), 0x90);
    result = write(pid, src, nop.data(), size);
    return result;
}

uintptr_t mem::read_pointer(mem_pid_t pid, uintptr_t src, std::vector<uintptr_t> offsets) {
    uintptr_t addr = src;
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        read(pid, (void*)addr, &addr, sizeof(addr));
        addr += offsets[i];
    }
    return addr;
}

uintptr_t mem::aob_scan(mem_pid_t pid, const char* pattern, const char* mask, char* begin, char* end)
{
    uintptr_t result = 0;
    char* current_address = begin;

    while (current_address < end)
    {
        memory_information mi;

        if (!query(pid, current_address, &mi))
        {
            return result;
        }

#if defined(_WIN32)
        if (mi.state == MEM_COMMIT && mi.protect != protection::NONE)
#else
        current_address = (char*)mi.base_address;
        if (mi.protect != protection::NONE)
#endif
        {
            uintptr_t old_protect = 0;
            char* buffer = new char[mi.size];

            if (protect(pid, mi.base_address, mi.size, protection::READ_WRITE_EXECUTE, &old_protect))
            {
                read(pid, mi.base_address, buffer, mi.size);
                protect(pid, mi.base_address, mi.size, old_protect, &old_protect);

                char* internal_address = 0;
                size_t pattern_length = std::strlen(mask);

                for (size_t i = 0; i < mi.size - pattern_length; i++)
                {
                    bool found = true;
                    for (size_t j = 0; j < pattern_length; j++)
                    {
                        if (mask[j] != '?' && pattern[j] != *(buffer + i + j))
                        {
                            found = false;
                            break;
                        }
                    }
                    if (found)
                    {
                        internal_address = buffer + i;
                    }
                }

                if (internal_address != 0)
                {
                    uintptr_t offset_from_buffer = internal_address - buffer;
                    result = (uintptr_t)current_address + offset_from_buffer;
                    delete[] buffer;
                    break;
                }
            }
            delete[] buffer;
        }
#if defined(_WIN32)
        current_address = current_address + mi.size;
#else
        current_address = (char*)mi.next_address;
        if (!current_address) return result;
#endif
    }
    return result;
}
