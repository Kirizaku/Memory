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

#if defined(_WIN32)
#define PROTECTION PAGE_EXECUTE_READWRITE
#else
#define PROTECTION PROT_EXEC | PROT_READ | PROT_WRITE
#endif

int main()
{
	mem_pid_t process_pid = mem::get_pid(PROCESS_NAME);
	stdcout << "Process PID: " << process_pid << "\n";

	mem_string process_name = mem::get_process_name(process_pid);
	stdcout << "Process Name: " << process_name << "\n";

	uintptr_t process_module = mem::get_module(process_pid, PROCESS_MODULE);
	stdcout << "Module Base: " << (void*)process_module << "\n";

	void* path_address = mem::allocate(process_pid, NULL, 4096, PROTECTION);
	stdcout << "Allocated address: " << path_address << "\n";

	int write_value = 12345;
	mem::write(process_pid, path_address, &write_value, sizeof(write_value));
	stdcout << "Written allocate value: " << write_value << "\n";

	uintptr_t read_value = 0;
	mem::read(process_pid, path_address, &read_value, sizeof(read_value));
	stdcout << "Read allocate value: " << read_value << "\n\n";

	stdcout << "Press [ENTER] to exit...";
	std::cin.get();

	mem::deallocate(process_pid, path_address, 4096);

	return 0;
}