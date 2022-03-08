#include "memory.h"

mem_uint64_t mem::mem_get_pid(mem_string process_name) {
	mem_uint64_t pid = 0;
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
	return pid;
}

mem_string mem::mem_get_process_name(mem_uint64_t pid) {
	mem_string process_name;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof(process_entry);

		if (Process32First(hSnap, &process_entry)) {
			do {
				if (pid == process_entry.th32ProcessID) {
					process_name = mem_string(process_entry.szExeFile);
					process_name = process_name.substr(process_name.rfind('\\', process_name.length()) + 1, process_name.length());
					break;
				}
			} while (Process32Next(hSnap, &process_entry));
		}
	}
	CloseHandle(hSnap);
	return process_name;
}

mem_uint64_t mem::mem_get_module(mem_uint64_t pid, mem_string module_name) {
	mem_uint64_t module_base = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 module_entry;
		module_entry.dwSize = sizeof(module_entry);
		if (Module32First(hSnap, &module_entry)) {
			do {
				if (!mem_cmp(module_entry.szModule, module_name.c_str()) || !mem_cmp(module_entry.szExePath, module_name.c_str())) {
					module_base = (mem_uint64_t)module_entry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &module_entry));
		}
	}
	CloseHandle(hSnap);
	return module_base;
}

mem_uint64_t mem::mem_load_module(mem_uint64_t pid, mem_string path) {
	mem_uint64_t module_base = 0;
	mem_size_t path_size = mem_len(path.c_str()) + 1;
	mem_void_t path_address = mem_allocate(pid, 0, path_size, PAGE_EXECUTE_READWRITE);
	if (path_address == 0) return module_base;
	mem_write(pid, path_address, (mem_cvoid_t*)path.c_str(), path_size);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
		HANDLE hThread = (HANDLE)CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, path_address, 0, 0);
		if (hThread) {
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		}
		CloseHandle(hProcess);
	}
	mem_deallocate(pid, path_address, path_size);
	module_base = mem_get_module(pid, path);
	return module_base;
}

mem_void_t mem::mem_allocate(mem_uint64_t pid, mem_void_t src, mem_size_t size, mem_uint64_t protection) {
	mem_void_t result = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
	result = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, protection);
	if (!result) result = FALSE;
	CloseHandle(hProcess);
	return result;
}

mem_bool mem::mem_deallocate(mem_uint64_t pid, mem_void_t src, mem_size_t size) {
	mem_bool result = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
	result = VirtualFreeEx(hProcess, src, 0, MEM_RELEASE) != 0 ? TRUE : FALSE;
	CloseHandle(hProcess);
	return result;
}

mem_bool mem::mem_protect(mem_uint64_t pid, mem_void_t src, mem_size_t size, mem_uint64_t protection, mem_p_uint64_t old_protection) {
	mem_bool result = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	mem_uint64_t old_protect = 0;
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
	result = VirtualProtectEx(hProcess, src, size, protection, &old_protect) != 0 ? TRUE : FALSE;
	if (old_protection) *old_protection = old_protect;
	CloseHandle(hProcess);
	return result;
}

mem_bool mem::mem_read(mem_uint64_t pid, mem_void_t src, mem_void_t dst, mem_size_t size) {
	mem_bool result = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
	result = ReadProcessMemory(hProcess, (mem_cvoid_t)src, dst, size, NULL) != 0 ? TRUE : FALSE;
	CloseHandle(hProcess);
	return result;
}

mem_bool mem::mem_write(mem_uint64_t pid, mem_void_t src, mem_void_t dst, mem_size_t size) {
	mem_bool result = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return result;
	result = WriteProcessMemory(hProcess, src, (mem_cvoid_t)dst, size, NULL) != 0 ? TRUE : FALSE;
	CloseHandle(hProcess);
	return result;
}

mem_bool mem::mem_nop_ex(mem_uint64_t pid, mem_void_t src, mem_size_t size) {
	mem_bool result = 0;
	BYTE* nop = new BYTE[size];
	if (!nop) return result;
	memset(nop, 0x90, size);
	result = mem_write(pid, src, nop, size);
	delete[] nop;
	return result;
}

mem_uint64_t mem::mem_read_pointer(mem_uint64_t pid, mem_uint64_t src, std::vector<mem_uint64_t> offsets) {
	mem_uint64_t addr = src;
	for (int i = 0; i < offsets.size(); ++i)
	{
		mem_read(pid, (mem_void_t*)addr, &addr, sizeof(addr));
		addr += offsets[i];
	}
	return addr;
}