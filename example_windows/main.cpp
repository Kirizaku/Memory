#include <iostream>
#include "../memory.h"

int main()
{
	mem_uint64_t process_pid = mem::mem_get_pid("example.exe");
	std::cout << "Process PID: " << process_pid << "\n";

	mem_string process_name = mem::mem_get_process_name(process_pid);
	std::cout << "Process Name: " << process_name << "\n";

	mem_uint64_t process_module = mem::mem_get_module(process_pid, "example.exe");
	std::cout << std::hex << "Module Base: " << process_module << "\n";

	mem_void_t path_address = mem::mem_allocate(process_pid, NULL, MAX_PATH, PAGE_EXECUTE_READWRITE);
	std::cout <<"Allocated address: " << path_address << std::dec << "\n";

	int write_value = 12345;
	mem::mem_write(process_pid, path_address, &write_value, sizeof(write_value));
	std::cout <<"Written allocate value: " << write_value << "\n";

	mem_uint64_t read_value = 0;
	mem::mem_read(process_pid, path_address, &read_value, sizeof(read_value));
	std::cout << "Read allocate value: " << read_value << "\n\n";

	mem::mem_deallocate(process_pid, path_address, MAX_PATH);

	std::cout << "Press [ENTER] to exit...";
	std::cin.get();
	return 0;
}