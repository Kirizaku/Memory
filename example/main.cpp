#include <iostream>
#include "../memory.h"

#if defined(_UNICODE)
#define stdcout std::wcout
#define PROCESS_NAME L"example"
#define PROCESS_MODULE L"example"
#else
#define stdcout std::cout
#define PROCESS_NAME "example"
#define PROCESS_MODULE "example"
#endif

int main()
{
	mem::mem_pid_t process_pid = mem::get_pid(PROCESS_NAME);
	stdcout << "Process PID: " << process_pid << "\n";

	mem::string_t process_name = mem::get_process_name(process_pid);
	stdcout << "Process Name: " << process_name << "\n";

	uintptr_t process_module = mem::get_module(process_pid, PROCESS_MODULE);
	stdcout << "Module Base: " << (void*)process_module << "\n\n";

	void* path_address = mem::allocate(process_pid, 0, 4096, mem::protection::READ_WRITE_EXECUTE);
	stdcout << "Allocated address: " << path_address << "\n";

	int write_value = 12345;
	mem::write(process_pid, path_address, &write_value, sizeof(write_value));
	stdcout << "Written allocate value: " << write_value << "\n";

	uintptr_t read_value = 0;
	mem::read(process_pid, path_address, &read_value, sizeof(read_value));
	stdcout << "Read allocate value: " << read_value << "\n\n";

	mem::memory_information mi;
	mem::query(process_pid, path_address, &mi);
	stdcout << "Query Base Address: " << mi.base_address << "\n";
	#if defined(__linux__)
	stdcout << "Query Next Address: " << mi.next_address << "\n";
	#endif
	stdcout << "Query size: " << (void*)mi.size << "\n";
	stdcout << "Query Protect: " << mi.protect << "\n";
	stdcout << "Query Flags/type: " << mi.type << "\n\n";

	stdcout << "Press [ENTER] to exit...";
	std::cin.get();

	mem::deallocate(process_pid, path_address, 4096); 

	return 0;
}