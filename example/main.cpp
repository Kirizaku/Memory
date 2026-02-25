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
    mem::mem_pid_t process_pid = mem::get_pid(PROCESS_NAME);
    cout << "Process PID: " << process_pid << "\n";

    mem::string_t process_name = mem::get_process_name(process_pid);
    cout << "Process Name: " << process_name << "\n";

    uintptr_t process_module = mem::get_module(process_pid, PROCESS_MODULE);
    cout << "Module Base: " << (void*)process_module << "\n";

    std::filesystem::path current_path = std::filesystem::current_path() / LIB_NAME;

    uintptr_t library_address = mem::load_module(process_pid, current_path.string());
    cout << "Module Base test-library: " << (void*)library_address << "\n";

    void* path_address = mem::allocate(process_pid, 0, 4096, mem::protection::READ_WRITE_EXECUTE);
    cout << "Allocated address: " << path_address << "\n";

    int write_value = 12345;
    mem::write(process_pid, path_address, &write_value, sizeof(write_value));
    cout << "Written allocate value: " << write_value << "\n";

    uintptr_t read_value = 0;
    mem::read(process_pid, path_address, &read_value, sizeof(read_value));
    cout << "Read allocate value: " << read_value << "\n\n";

    mem::memory_information mi;
    mem::query(process_pid, path_address, &mi);
    cout << "Query Base Address: " << mi.base_address << "\n";
    #if defined(__linux__)
    cout << "Query Next Address: " << mi.next_address << "\n";
    #endif
    cout << "Query size: " << (void*)mi.size << "\n";
    cout << "Query Protect: " << mi.protect << "\n";
    cout << "Query Flags/type: " << mi.type << "\n\n";

    cout << "Press [ENTER] to exit...";
    std::cin.get();

    mem::deallocate(process_pid, path_address, 4096);

    return 0;
}
