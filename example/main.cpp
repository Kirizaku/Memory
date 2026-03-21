#include <iostream>
#include <filesystem>
#include "../memory.h"

#if defined(_WIN32)
#define EXE_EXTENSION ".exe"
#else
#define EXE_EXTENSION ""
#endif

#if defined(_UNICODE)
#define cout std::wcout
#define PROCESS_NAME L"test-target" EXE_EXTENSION
#define PROCESS_MODULE L"test-target" EXE_EXTENSION
#else
#define cout std::cout
#define PROCESS_NAME "test-target" EXE_EXTENSION
#define PROCESS_MODULE "test-target" EXE_EXTENSION
#endif

#if defined(_WIN32)
#define LIB_NAME "test-library.dll"
#else
#define LIB_NAME "test-library.so"
#endif

int main()
{
    cout << "========== PROCESS INFORMATION ==========\n";
    mem::mem_pid_t process_pid = mem::get_pid(PROCESS_NAME);
    cout << "Process PID: " << process_pid << "\n";

    mem::string_t process_name = mem::get_process_name(process_pid);
    cout << "Process Name: " << process_name << "\n";

    uintptr_t process_module = mem::get_module(process_pid, PROCESS_MODULE);
    cout << "Module Base: " << (void*)process_module << "\n\n";

    cout << "========== MODULE LOAD ==========\n";
    std::filesystem::path current_path = std::filesystem::current_path() / LIB_NAME;

    auto custom_module = mem::load_module(process_pid, current_path.string());
    cout << "Module Base test-library: " << (void*)custom_module.base << "\n\n";

    cout << "========== MEMORY ALLOCATION ==========\n";
    void* path_address = mem::allocate(process_pid, 0, 4096, mem::protection::READ_WRITE_EXECUTE);
    cout << "Allocated address: " << path_address << "\n";

    int write_value = 12345;
    mem::write(process_pid, path_address, &write_value, sizeof(write_value));
    cout << "Written value: " << write_value << "\n";

    int read_value = 0;
    mem::read(process_pid, path_address, &read_value, sizeof(read_value));
    cout << "Read value: " << read_value << "\n\n";

    cout << "========== MEMORY QUERY ==========\n";
    mem::memory_information mi;
    mem::query(process_pid, path_address, &mi);
    cout << "Base Address: " << mi.base_address << "\n";
#if defined(__linux__)
    cout << "Next Address: " << mi.next_address << "\n";
#endif
    cout << "Size: " << mi.size << "\n";
    cout << "Protect: " << mi.protect << "\n";
    cout << "Type: " << mi.type << "\n\n";

    cout << "========== CLEANUP ==========\n";
    if (custom_module.base) {
        bool result = mem::unload_module(process_pid, custom_module);
        cout << "Unload module: " << (result ? "SUCCESS" : "FAILED") << "\n";
    }

    if (path_address) {
        bool result = mem::deallocate(process_pid, path_address, 4096);
        cout << "Memory deallocated: " << (result ? "SUCCESS" : "FAILED") << "\n";
    }

    cout << "\nPress [ENTER] to exit...";
    std::cin.get();

    return 0;
}