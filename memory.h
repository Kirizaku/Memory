/*
* Memory Hacking Library C++
* by Kirizaku
* version 1.0.1
* https://github.com/kirizaku/memory

Licensed under the MIT License <http://opensource.org/licenses/MIT>.

Copyright (c) 2022 Rudeus Kirigaya <https://github.com/kirizaku>

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

#pragma once
#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <string>
#include <cstring>
#include <vector>
#include <iostream>
#include <sstream>
#include <fstream>

#if defined(_UNICODE)
typedef std::wstring mem_string;
#define mem_len std::wcslen
#define mem_cmp std::wcscmp
#else
typedef std::string mem_string;
#define mem_len std::strlen
#define mem_cmp std::strcmp
#endif

#if defined(_WIN32)
#include <Windows.h>
#include <TlHelp32.h>

typedef DWORD mem_pid_t;

#elif defined(__linux__)
#include <dirent.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dlfcn.h>

typedef pid_t mem_pid_t;
#endif

namespace mem {
#if defined(__linux__)
	extern void* inject_syscall(mem_pid_t pid, int syscall_id, void* arg0, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5);
#endif
	extern mem_pid_t get_pid(mem_string process_name);
	extern mem_string get_process_name(mem_pid_t pid);
	extern uintptr_t get_module(mem_pid_t pid, mem_string module_name);
	extern uintptr_t load_module(mem_pid_t pid, mem_string path);
	extern void* allocate(mem_pid_t pid, void* src, size_t size, uintptr_t protection);
	extern bool deallocate(mem_pid_t pid, void* src, size_t size);
	extern bool protect(mem_pid_t pid, void* src, size_t size, uintptr_t protection, uintptr_t *old_protection);
	extern bool read(mem_pid_t pid, void* src, void* dst, size_t size);
	extern bool write(mem_pid_t pid, void* src, void* dst, size_t size);
	extern bool nop_ex(mem_pid_t pid, void* src, size_t size);
	extern uintptr_t read_pointer(mem_pid_t pid, uintptr_t src, std::vector<uintptr_t> offsets);
}

#endif	// _MEMORY_H_
