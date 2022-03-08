/*
* Memory Hacking Library C++
* by Kirizaku
* version 1.0.0
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
#include <vector>

#if defined(_UNICODE)
typedef wchar_t mem_char;
typedef std::wstring mem_string;
#define mem_len wcslen
#define mem_cmp wcscmp
#else
typedef char mem_char;
typedef std::string mem_string;
#define mem_len strlen
#define mem_cmp strcmp
#endif

#include <Windows.h>
#include <TlHelp32.h>

typedef DWORD mem_uint64_t;
typedef PDWORD mem_p_uint64_t;
typedef BOOL mem_bool;
typedef LPVOID mem_void_t;
typedef LPCVOID mem_cvoid_t;
typedef SIZE_T mem_size_t;

namespace mem {
	extern inline mem_uint64_t mem_get_pid(mem_string process_name);
	extern inline mem_string mem_get_process_name(mem_uint64_t pid);
	extern inline mem_uint64_t mem_get_module(mem_uint64_t pid, mem_string module_name);
	extern inline mem_uint64_t mem_load_module(mem_uint64_t pid, mem_string path);
	extern inline mem_void_t mem_allocate(mem_uint64_t pid, mem_void_t src, mem_size_t size, mem_uint64_t protection);
	extern inline mem_bool mem_deallocate(mem_uint64_t pid, mem_void_t src, mem_size_t size);
	extern inline mem_bool mem_protect(mem_uint64_t pid, mem_void_t src, mem_size_t size, mem_uint64_t protection, mem_p_uint64_t old_protection);
	extern inline mem_bool mem_read(mem_uint64_t pid, mem_void_t src, mem_void_t dst, mem_size_t size);
	extern inline mem_bool mem_write(mem_uint64_t pid, mem_void_t src, mem_void_t dst, mem_size_t size);
	extern inline mem_bool mem_nop_ex(mem_uint64_t pid, mem_void_t src, mem_size_t size);
	extern inline mem_uint64_t mem_read_pointer(mem_uint64_t pid, mem_uint64_t src, std::vector<mem_uint64_t> offsets);
}

#endif	// _MEMORY_H_