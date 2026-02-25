#include <iostream>

#if defined(_WIN32)

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            std::cout << "Hello from library!" << std::endl;
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

#else

__attribute__((constructor))
void init()
{
    std::cout << "Hello from library!" << std::endl;
}

#endif
