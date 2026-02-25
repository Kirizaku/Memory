#include <iostream>
#include <thread>
#include <chrono>

int main()
{
    while (true) {
        std::cout << "Hello world!" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));

    }
    return 0;
}
